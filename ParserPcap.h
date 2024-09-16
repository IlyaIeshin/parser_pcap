#ifndef PARSER_PCAP_H
#define PARSER_PCAP_H

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <arpa/inet.h>

struct Packet
{
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t  protocol;
};

struct PcapHeader
{
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapRecordHeader
{
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct EthernetHeader
{
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t protocol;
};

struct IPHeader
{
    uint8_t vers_and_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t identification;
    uint16_t flags;
    uint8_t ttl;
    uint8_t protocol;
    uint8_t checksum;
    uint32_t src_addr;
    uint32_t dest_addr;
};

struct TCPHeader
{
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint16_t data_offset;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct UDPHeader
{
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

inline PcapHeader pcaphdr;

class ParserPcap
{
public:
    ParserPcap(const std::string& path_file_pcap);
    ~ParserPcap();
    std::pair<Packet, std::vector<uint8_t>> readRecord();
    bool eof() const;
private:
    std::ifstream file;
};

#endif

