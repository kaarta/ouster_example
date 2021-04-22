/**
 * @file
 * @brief Example node to publish raw OS-1 output on ROS topics
 *
 * ROS Parameters
 * os1_hostname: hostname or IP in dotted decimal form of the sensor
 * os1_udp_dest: hostname or IP where the sensor will send data packets
 * os1_lidar_port: port to which the sensor should send lidar data
 * os1_imu_port: port to which the sensor should send imu data
 */

#include <ros/console.h>
#include <ros/ros.h>
#include <fstream>
#include <sstream>
#include <string>

#include "ouster/os1_packet.h"
#include "ouster/os1_util.h"
#include "ouster_ros/OS1ConfigSrv.h"
#include "ouster_ros/PacketMsg.h"
#include "ouster_ros/os1_ros.h"

using PacketMsg = ouster_ros::PacketMsg;
using OS1ConfigSrv = ouster_ros::OS1ConfigSrv;
namespace OS1 = ouster::OS1;

// fill in values that could not be parsed from metadata
void populate_metadata_defaults(OS1::sensor_info& info,
                                const std::string& specified_lidar_mode) {
    if (!info.hostname.size()) info.hostname = "UNKNOWN";

    if (!info.sn.size()) info.sn = "UNKNOWN";

    OS1::version v = OS1::version_of_string(info.fw_rev);
    if (v == OS1::invalid_version)
        ROS_WARN("Unknown sensor firmware version; output may not be reliable");
    else if (v < OS1::min_version)
        ROS_WARN("Firmware < %s not supported; output may not be reliable",
                 to_string(OS1::min_version).c_str());

    if (!info.mode) {
        ROS_WARN(
            "Lidar mode not found in metadata; output may not be reliable");
        info.mode = OS1::lidar_mode_of_string(specified_lidar_mode);
    }

    if (info.beam_azimuth_angles.empty() || info.beam_altitude_angles.empty()) {
        ROS_WARN("Beam angles not found in metadata; using design values");
        info.beam_azimuth_angles = OS1::beam_azimuth_angles;
        info.beam_altitude_angles = OS1::beam_altitude_angles;
    }

    if (info.imu_to_sensor_transform.empty() ||
        info.lidar_to_sensor_transform.empty()) {
        ROS_WARN("Frame transforms not found in metadata; using design values");
        info.imu_to_sensor_transform = OS1::imu_to_sensor_transform;
        info.lidar_to_sensor_transform = OS1::lidar_to_sensor_transform;
    }
}

// try to read metadata file
std::string read_metadata(const std::string& meta_file) {
    if (meta_file.size()) {
        ROS_INFO("Reading metadata from %s", meta_file.c_str());
    } else {
        ROS_WARN("No metadata file specified");
        return "";
    }

    std::stringstream buf{};
    std::ifstream ifs{};
    ifs.open(meta_file);
    buf << ifs.rdbuf();
    ifs.close();

    if (!ifs)
        ROS_WARN("Failed to read %s; check that the path is valid",
                 meta_file.c_str());

    return buf.str();
}

// try to write metadata file
void write_metadata(const std::string& meta_file, const std::string& metadata) {
    std::ofstream ofs;
    ofs.open(meta_file);
    ofs << metadata << std::endl;
    ofs.close();
    if (ofs) {
        ROS_INFO("Wrote metadata to %s", meta_file.c_str());
    } else {
        ROS_WARN("Failed to write metadata to %s; check that the path is valid",
                 meta_file.c_str());
    }
}

#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>

  // from https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut6.html
  /* 4 bytes IP address */
  typedef struct ip_address{
      u_char byte1;
      u_char byte2;
      u_char byte3;
      u_char byte4;
  }ip_address;

  /* IPv4 header */
  typedef struct ip_header{
      u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
      u_char  tos;            // Type of service 
      u_short tlen;           // Total length 
      u_short identification; // Identification
      u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
      u_char  ttl;            // Time to live
      u_char  proto;          // Protocol
      u_short crc;            // Header checksum
      ip_address  saddr;      // Source address
      ip_address  daddr;      // Destination address
      u_int   op_pad;         // Option + Padding
  }ip_header;

  /* UDP header*/
  typedef struct udp_header{
      u_short sport;          // Source port
      u_short dport;          // Destination port
      u_short len;            // Datagram length
      u_short crc;            // Checksum
  }udp_header;

// Example command line to convert pcap:
// roslaunch ouster_ros pcap_to_bag.launch pcap_filename:=/home/kaarta/Downloads/ouster-1024x20.pcap

bool read_pcap(ros::NodeHandle& nh, std::string filename)
{
  pcap_t *pcap_;
  auto lidar_packet_pub = nh.advertise<PacketMsg>("lidar_packets", 1280);
  auto imu_packet_pub = nh.advertise<PacketMsg>("imu_packets", 100);

  ros::WallDuration(1).sleep();

  char errbuf_[PCAP_ERRBUF_SIZE];

  if ((pcap_ = pcap_open_offline(filename.c_str(), errbuf_) ) == NULL)
  {
    ROS_FATAL("Error opening pcap file %s", filename.c_str());
    return false;
  }

  PacketMsg lidar_packet, imu_packet;
  lidar_packet.buf.resize(OS1::lidar_packet_bytes + 1);
  imu_packet.buf.resize(OS1::imu_packet_bytes + 1);
  int lidar_counter = 0, imu_counter = 0;
  ros::Time last_time;

  struct pcap_pkthdr *header;
  const u_char *pkt_data;

  while (ros::ok())
  {
    ros::spinOnce();
    int res;
    if ((res = pcap_next_ex(pcap_, &header, &pkt_data)) >= 0)
    {
      // ROS_INFO_STREAM("header length: "<<header->len);
      // Skip packets not for the correct port and from the
      // selected IP address.
      // if (0 == pcap_offline_filter(&pcap_packet_filter_,
      //                               header, pkt_data))
      //   continue;
    
      /* retireve the position of the ip header */
      ip_header *ih;
      udp_header *uh;
      u_int ip_len;
      u_short dport/* ,dport */;
      ih = (ip_header *) (pkt_data + 14); //length of ethernet header

      /* retireve the position of the udp header */
      ip_len = (ih->ver_ihl & 0xf) * 4;
      uh = (udp_header *) ((u_char*)ih + ip_len);

      /* convert from network byte order to host byte order */
      dport = ntohs( uh->dport );
      // dport = ntohs( uh->dport );

      ros::Time packet_time(header->ts.tv_sec, header->ts.tv_usec * 1000);

      // hmp: In processing a pcap file, it appears there may have been out-of-order packets
      // causing this to sleep for a LONG time. Not sure if just skipping to the next one
      // is always the right thing in general.
      if (!last_time.isZero() && packet_time>last_time){
        (packet_time-last_time).sleep();
      }
      else{
        last_time = packet_time;
        continue;
      }

      last_time = packet_time;

      // ROS_INFO_STREAM("Got data on port: " << dport);
      if (dport == 7502){
        // velodyne point data
        memcpy(lidar_packet.buf.data(), pkt_data+42, OS1::lidar_packet_bytes);
        lidar_packet_pub.publish(lidar_packet);
        lidar_counter++;
      }
      else if(dport == 7503)
      {
        // velodyne point data
        memcpy(imu_packet.buf.data(), pkt_data+42, OS1::imu_packet_bytes);
        imu_packet_pub.publish(lidar_packet);
        imu_counter++;
      }
      std::cout << "Published: lidar_packets = " << lidar_counter << ", imu_packets = " << imu_counter << "\r";
      std::cout.flush();
}
    else{
      break;
    }
  }

  std::cout << std::endl;
  // ROS_INFO("Read %d packets", counter);

  // I can't figure out how to rewind the file, because it
  // starts with some kind of header.  So, close the file
  // and reopen it with pcap.
  pcap_close(pcap_);
  return lidar_counter > 0 && imu_counter > 0;
}

int connection_loop(ros::NodeHandle& nh, OS1::client& cli) {
    auto lidar_packet_pub = nh.advertise<PacketMsg>("lidar_packets", 1280);
    auto imu_packet_pub = nh.advertise<PacketMsg>("imu_packets", 100);

    PacketMsg lidar_packet, imu_packet;
    lidar_packet.buf.resize(OS1::lidar_packet_bytes + 1);
    imu_packet.buf.resize(OS1::imu_packet_bytes + 1);

    while (ros::ok()) {
        auto state = OS1::poll_client(cli);
        if (state == OS1::EXIT) {
            ROS_INFO("poll_client: caught signal, exiting");
            return EXIT_SUCCESS;
        }
        if (state & OS1::ERROR) {
            ROS_ERROR("poll_client: returned error");
            return EXIT_FAILURE;
        }
        if (state & OS1::LIDAR_DATA) {
            if (OS1::read_lidar_packet(cli, lidar_packet.buf.data()))
                lidar_packet_pub.publish(lidar_packet);
        }
        if (state & OS1::IMU_DATA) {
            if (OS1::read_imu_packet(cli, imu_packet.buf.data()))
                imu_packet_pub.publish(imu_packet);
        }
        ros::spinOnce();
    }
    return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
    ros::init(argc, argv, "os1_node");
    ros::NodeHandle nh("~");

    OS1::sensor_info info{};
    auto srv =
        nh.advertiseService<OS1ConfigSrv::Request, OS1ConfigSrv::Response>(
            "os1_config",
            [&](OS1ConfigSrv::Request&, OS1ConfigSrv::Response& res) {
                res.hostname = info.hostname;
                res.lidar_mode = to_string(info.mode);
                res.beam_azimuth_angles = info.beam_azimuth_angles;
                res.beam_altitude_angles = info.beam_altitude_angles;
                res.imu_to_sensor_transform = info.imu_to_sensor_transform;
                res.lidar_to_sensor_transform = info.lidar_to_sensor_transform;
                return true;
            });

    // empty indicates "not set" since roslaunch xml can't optionally set params
    auto hostname = nh.param("os1_hostname", std::string{});
    auto udp_dest = nh.param("os1_udp_dest", std::string{});
    auto lidar_port = nh.param("os1_lidar_port", 0);
    auto imu_port = nh.param("os1_imu_port", 0);
    auto replay = nh.param("replay", false);
    replay = replay || nh.param("/use_sim_time", false);
    auto lidar_mode = nh.param("lidar_mode", std::string{});
    auto timestamp_mode = nh.param("timestamp_mode", std::string{});
    auto pcap_filename = nh.param("pcap_filename", std::string{});

    // fall back to metadata file name based on hostname, if available
    auto meta_file = nh.param("metadata", std::string{});
    if (!meta_file.size() && hostname.size()) meta_file = hostname + ".json";

    if (lidar_mode.size()) {
        if (replay) ROS_WARN("Lidar mode set in replay mode. May be ignored");
    } else {
        lidar_mode = OS1::to_string(OS1::MODE_1024x10);
    }

    if (!OS1::lidar_mode_of_string(lidar_mode)) {
        ROS_ERROR("Invalid lidar mode %s", lidar_mode.c_str());
        return EXIT_FAILURE;
    }

    if (not timestamp_mode.size()) {
        timestamp_mode = OS1::to_string(OS1::TIME_FROM_INTERNAL_OSC);
    }

    if (!OS1::timestamp_mode_of_string(timestamp_mode)) {
        ROS_ERROR("Invalid timestamp mode %s", timestamp_mode.c_str());
        return EXIT_FAILURE;
    }

    if (!replay && (!hostname.size() || !udp_dest.size()) && pcap_filename.length() == 0) {
        ROS_ERROR("Must specify both hostname and udp destination");
        return EXIT_FAILURE;
    }

    // populate info for config service
    // hmp: It looks like the metadata file is only applicable in replay?
    // This code crashes if no metadata file is supplied... i.e. in live scanning or pcap conversion
    // std::string metadata = read_metadata(meta_file);
    // std::cout << "metadata: " << metadata;
    // info = OS1::parse_metadata(metadata);
    // std::cout << "info:\nbeam_altitude_angles:\n" << info.beam_altitude_angles.front() << std::endl;

    if (replay) {
        ROS_INFO("Running in replay mode");

        // populate info for config service
        std::string metadata = read_metadata(meta_file);
        info = OS1::parse_metadata(metadata);
        populate_metadata_defaults(info, lidar_mode);

        ROS_INFO("Using lidar_mode: %s", OS1::to_string(info.mode).c_str());
        ROS_INFO("Sensor sn: %s firmware rev: %s", info.sn.c_str(),
                 info.fw_rev.c_str());

        // just serve config service
        ROS_INFO("os1_node spinning");
        ros::spin();
        return EXIT_SUCCESS;
    } else if (pcap_filename.length() > 0) {
        sleep(1);
        ros::spinOnce();
        // populate info for config service
        // hmp: I don't think the metadata is relevant just to publish packets from a pcap file?
        // std::string metadata = read_metadata(meta_file);
        // std::cout << "metadata: " << metadata;
        // info = OS1::parse_metadata(metadata);
        // std::cout << "info:\nbeam_altitude_angles:\n" << info.beam_altitude_angles.front() << std::endl;

        return read_pcap(nh, pcap_filename);
    } else {
        ROS_INFO("Connecting to sensor at %s...", hostname.c_str());

        ROS_INFO("Sending data to %s using lidar_mode: %s", udp_dest.c_str(),
                 lidar_mode.c_str());

        auto cli = OS1::init_client(hostname, udp_dest,
                                    OS1::lidar_mode_of_string(lidar_mode),
                                    OS1::timestamp_mode_of_string(timestamp_mode),
                                    lidar_port, imu_port);

        if (!cli) {
            ROS_ERROR("Failed to initialize sensor at: %s", hostname.c_str());
            return EXIT_FAILURE;
        }
        ROS_INFO("Sensor reconfigured successfully, waiting for data...");

        // write metadata file to cwd (usually ~/.ros)
        auto metadata = OS1::get_metadata(*cli);
        write_metadata(meta_file, metadata);

        // populate sensor info
        info = OS1::parse_metadata(metadata);
        populate_metadata_defaults(info, "");

        ROS_INFO("Sensor sn: %s firmware rev: %s", info.sn.c_str(),
                 info.fw_rev.c_str());

        // publish packet messages from the sensor
        return connection_loop(nh, *cli);
    }
}
