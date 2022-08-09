#pragma once

#include <cstdint>
#include <iostream>
#include <fstream>
#include <pcap.h>

#include "gilgil_lib/arphdr.h"
#include "gilgil_lib/ethhdr.h"

struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};

struct Ip_Mac_map {
    Mac eth_smac;
    Mac eth_dmac;
    Mac arp_smac;
    Ip arp_sip;
    Mac arp_tmac;
    Ip arp_tip;
};

class ArpInfector {
private:
    char* device_;

    Mac* my_MAC_;
    Mac* victim_MAC_;

    Ip* victim_ip_;
    Ip* target_ip_;

    pcap_t* handle_;
    char errbuf_[PCAP_ERRBUF_SIZE];

    void send_arp_request(Ip_Mac_map* ipmac_map, int type);
    Mac* get_my_MAC();
    Mac* capture_arp_packet(const u_char* packet);

public:
    //constructor
    ArpInfector(char* device, Ip* sender_ip, Ip* target_ip);
    ~ArpInfector();
    
    void get_victim_MAC();
    void infect_victim_ARP_table();
};
