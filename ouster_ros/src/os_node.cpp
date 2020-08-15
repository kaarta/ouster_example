/**
 * @file
 * @brief Example node to publish raw sensor output on ROS topics
 *
 * ROS Parameters
 * sensor_hostname: hostname or IP in dotted decimal form of the sensor
 * udp_dest: hostname or IP where the sensor will send data packets
 * lidar_port: port to which the sensor should send lidar data
 * imu_port: port to which the sensor should send imu data
 */

#include <ros/console.h>
#include <ros/ros.h>

#include <fstream>
#include <sstream>
#include <string>

#include "ouster/types.h"
#include "ouster_ros/OSConfigSrv.h"
#include "ouster_ros/PacketMsg.h"
#include "ouster_ros/ros.h"

using PacketMsg = ouster_ros::PacketMsg;
using OSConfigSrv = ouster_ros::OSConfigSrv;
namespace sensor = ouster::sensor;

// fill in values that could not be parsed from metadata
void populate_metadata_defaults(sensor::sensor_info& info,
                                sensor::lidar_mode specified_lidar_mode) {
    if (!info.hostname.size()) info.hostname = "UNKNOWN";

    if (!info.sn.size()) info.sn = "UNKNOWN";

    ouster::util::version v = ouster::util::version_of_string(info.fw_rev);
    if (v == ouster::util::invalid_version)
        ROS_WARN("Unknown sensor firmware version; output may not be reliable");
    else if (v < sensor::min_version)
        ROS_WARN("Firmware < %s not supported; output may not be reliable",
                 to_string(sensor::min_version).c_str());

    if (!info.mode) {
        ROS_WARN(
            "Lidar mode not found in metadata; output may not be reliable");
        info.mode = specified_lidar_mode;
    }

    if (!info.prod_line.size()) info.prod_line = "UNKNOWN";

    if (info.beam_azimuth_angles.empty() || info.beam_altitude_angles.empty()) {
        ROS_WARN("Beam angles not found in metadata; using design values");
        info.beam_azimuth_angles = sensor::gen1_azimuth_angles;
        info.beam_altitude_angles = sensor::gen1_altitude_angles;
    }

    if (info.imu_to_sensor_transform.empty() ||
        info.lidar_to_sensor_transform.empty()) {
        ROS_WARN("Frame transforms not found in metadata; using design values");
        info.imu_to_sensor_transform = sensor::imu_to_sensor_transform;
        info.lidar_to_sensor_transform = sensor::lidar_to_sensor_transform;
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
        ROS_INFO("Wrote metadata to $ROS_HOME/%s", meta_file.c_str());
    } else {
        ROS_WARN("Failed to write metadata to %s; check that the path is valid",
                 meta_file.c_str());
    }
}

int connection_loop(ros::NodeHandle& nh, sensor::client& cli,
                    const sensor::data_format& df) {
    auto lidar_packet_pub = nh.advertise<PacketMsg>("lidar_packets", 1280);
    auto imu_packet_pub = nh.advertise<PacketMsg>("imu_packets", 100);

    auto pf = sensor::get_format(df);

    PacketMsg lidar_packet, imu_packet;
    lidar_packet.buf.resize(pf.lidar_packet_size + 1);
    imu_packet.buf.resize(pf.imu_packet_size + 1);

    while (ros::ok()) {
        auto state = sensor::poll_client(cli);
        if (state == sensor::EXIT) {
            ROS_INFO("poll_client: caught signal, exiting");
            return EXIT_SUCCESS;
        }
        if (state & sensor::CLIENT_ERROR) {
            ROS_ERROR("poll_client: returned error");
            return EXIT_FAILURE;
        }
        if (state & sensor::LIDAR_DATA) {
            if (sensor::read_lidar_packet(cli, lidar_packet.buf.data(), pf))
                lidar_packet_pub.publish(lidar_packet);
        }
        if (state & sensor::IMU_DATA) {
            if (sensor::read_imu_packet(cli, imu_packet.buf.data(), pf))
                imu_packet_pub.publish(imu_packet);
        }
        ros::spinOnce();
    }
    return EXIT_SUCCESS;
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

bool read_pcap(ros::NodeHandle& nh, const std::string& filename, const sensor::data_format& df)
{
  auto lidar_packet_pub = nh.advertise<PacketMsg>("lidar_packets", 1280);
  auto imu_packet_pub = nh.advertise<PacketMsg>("imu_packets", 100);
  ros::WallDuration(1).sleep();

  auto pf = sensor::get_format(df);

  PacketMsg lidar_packet, imu_packet;
  lidar_packet.buf.resize(pf.lidar_packet_size + 1);
  imu_packet.buf.resize(pf.imu_packet_size + 1);

  int counter = 0;

  pcap_t *pcap_;
  char errbuf_[PCAP_ERRBUF_SIZE];

  if ((pcap_ = pcap_open_offline(filename.c_str(), errbuf_) ) == NULL)
  {
    ROS_FATAL("Error opening pcap file %s", filename.c_str());
    return false;
  }

  struct pcap_pkthdr *header;
  const u_char *pkt_data;

  ros::Time last_time;

  while (true)
  {
    ros::spinOnce();
    int res;
    if ((res = pcap_next_ex(pcap_, &header, &pkt_data)) >= 0)
    {
      // ROS_INFO_STREAM("header length: "<<header->len);

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

      if (dport == 7502)
      {
        memcpy(lidar_packet.buf.data(), pkt_data+42, pf.lidar_packet_size);
        lidar_packet_pub.publish(lidar_packet);
        ++counter;
      }
      else if(dport == 7503)
      {
        memcpy(imu_packet.buf.data(), pkt_data+42, pf.imu_packet_size);
        imu_packet_pub.publish(lidar_packet);
      }

      ros::Time packet_time(header->ts.tv_sec, header->ts.tv_usec * 1000);
      // ROS_INFO_STREAM("Got data on port: " << dport);

      if (!last_time.isZero())
        (packet_time-last_time).sleep();

      last_time = packet_time;
    }
  }

  ROS_INFO("Read %d lidar packets", counter);

  // I can't figure out how to rewind the file, because it
  // starts with some kind of header.  So, close the file
  // and reopen it with pcap.
  pcap_close(pcap_);
  return counter > 0;                   // success
}

int main(int argc, char** argv)
{
    ros::init(argc, argv, "os_node");
    ros::NodeHandle nh("~");

    std::string published_metadata;
    auto srv = nh.advertiseService<OSConfigSrv::Request, OSConfigSrv::Response>(
        "os_config", [&](OSConfigSrv::Request&, OSConfigSrv::Response& res) {
            if (published_metadata.size()) {
                res.metadata = published_metadata;
                return true;
            } else
                return false;
        });

    // empty indicates "not set" since roslaunch xml can't optionally set params
    auto hostname = nh.param("sensor_hostname", std::string{});
    auto udp_dest = nh.param("udp_dest", std::string{});
    auto lidar_port = nh.param("lidar_port", 0);
    auto imu_port = nh.param("imu_port", 0);
    auto replay = nh.param("replay", false);
    auto lidar_mode_arg = nh.param("lidar_mode", std::string{});
    auto timestamp_mode_arg = nh.param("timestamp_mode", std::string{});
    auto pcap_filename = nh.param("pcap_filename", std::string{});

    // fall back to metadata file name based on hostname, if available
    auto meta_file = nh.param("metadata", std::string{});
    if (!meta_file.size() && hostname.size()) meta_file = hostname + ".json";

    // set lidar mode from param
    sensor::lidar_mode lidar_mode = sensor::MODE_UNSPEC;
    if (lidar_mode_arg.size()) {
        if (replay) ROS_WARN("Lidar mode set in replay mode. May be ignored");

        lidar_mode = sensor::lidar_mode_of_string(lidar_mode_arg);
        if (!lidar_mode) {
            ROS_ERROR("Invalid lidar mode %s", lidar_mode_arg.c_str());
            return EXIT_FAILURE;
        }
    }

    // set timestamp mode from param
    sensor::timestamp_mode timestamp_mode = sensor::TIME_FROM_UNSPEC;
    if (timestamp_mode_arg.size()) {
        if (replay)
            ROS_WARN("Timestamp mode set in replay mode. Will be ignored");

        timestamp_mode = sensor::timestamp_mode_of_string(timestamp_mode_arg);
        if (!timestamp_mode) {
            ROS_ERROR("Invalid timestamp mode %s", timestamp_mode_arg.c_str());
            return EXIT_FAILURE;
        }
    }

    if (!replay && (!hostname.size() || !udp_dest.size())) {
        ROS_ERROR("Must specify both hostname and udp destination");
        return EXIT_FAILURE;
    }


    if (replay) {
        ROS_INFO("Running in replay mode");

        // populate info for config service
        std::string metadata = read_metadata(meta_file);
        auto info = sensor::parse_metadata(metadata);
        populate_metadata_defaults(info, lidar_mode);
        published_metadata = to_string(info);

        ROS_INFO("Using lidar_mode: %s", sensor::to_string(info.mode).c_str());
        ROS_INFO("%s sn: %s firmware rev: %s", info.prod_line.c_str(),
                 info.sn.c_str(), info.fw_rev.c_str());

        if (pcap_filename.length())
        {
          read_pcap(nh, pcap_filename, info.format);
        }

        // just serve config service
        ros::spin();
        return EXIT_SUCCESS;
    } else {
        ROS_INFO("Connecting to %s; sending data to %s", hostname.c_str(),
                 udp_dest.c_str());
        ROS_INFO("Waiting for sensor to initialize ...");

        auto cli = sensor::init_client(hostname, udp_dest, lidar_mode,
                                       timestamp_mode, lidar_port, imu_port);

        if (!cli) {
            ROS_ERROR("Failed to initialize sensor at: %s", hostname.c_str());
            return EXIT_FAILURE;
        }
        ROS_INFO("Sensor initialized successfully");

        // write metadata file to cwd (usually ~/.ros)
        auto metadata = sensor::get_metadata(*cli);
        write_metadata(meta_file, metadata);

        // populate sensor info
        auto info = sensor::parse_metadata(metadata);
        populate_metadata_defaults(info, sensor::MODE_UNSPEC);
        published_metadata = to_string(info);

        ROS_INFO("Using lidar_mode: %s", sensor::to_string(info.mode).c_str());
        ROS_INFO("%s sn: %s firmware rev: %s", info.prod_line.c_str(),
                 info.sn.c_str(), info.fw_rev.c_str());

        // publish packet messages from the sensor
        return connection_loop(nh, *cli, info.format);
    }
}
