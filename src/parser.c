#include "parser.h"
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

void parse_packet(const struct pcap_pkthdr *header, const u_char *packet) {
	// we need an ethernet header..
	struct ether_header *eth = (struct ether_header *)packet;
	printf("Ethernet: Src MAC: %s, Dst MAC: %s\n",
		ether_ntoa((struct ether_addr *)eth->ether_shost),
		ether_ntoa((struct ether_addr *)eth->ether_dhost));

	// now we have to check for ip packet and if yes then check for tcp/udp packet

	// checking for ip packet
	if(ntohs(eth->ether_type) == ETHERTYPE_IP) {
		struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
		printf("IP: Src: %s, Dst: %s, Protocol: %d\n",
			inet_ntoa(ip_hdr->ip_src),
			inet_ntoa(ip_hdr->ip_dst),
			ip_hdr->ip_p);

		// good, now just check if its tcp or udp
		if(ip_hdr->ip_p == IPPROTO_TCP) {
			struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl*4);
			printf("TCP: Src PortL %d, Dst Port: %d\n",
				ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest));
		} else if(ip_hdr->ip_p == IPPROTO_UDP) {
			struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl*4);
			printf("TCP: Src PortL %d, Dst Port: %d\n",
                                ntohs(udp_hdr->source), ntohs(udp_hdr->dest));
		}

	}
	printf("Packet length: %d bytes\n\n", header->len);
}
