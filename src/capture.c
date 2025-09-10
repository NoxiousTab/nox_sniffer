#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "capture.h"
#include "parser.h"

static int protocol_filter = 0;

int packet_handler(struct pcap_pkthdr *header, const u_char *data) {
	parse_packet(header, data);
	return 0;
}


int start_capture(const char *interface, const char *protocol) {
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *device = NULL;

	if(!strcmp(protocol, "tcp")) protocol_filter = 1;
	else if(!strcmp(protocol, "udp")) protocol_filter = 2;
	else if(!strcmp(protocol, "icmp")) protocol_filter = 3;
	else protocol_filter = 0;

	// we want to list the devices
	if(pcap_findalldevs(&alldevs, errbuff) == -1) {
		fprintf(stderr, "Error finding devices: %s\n", errbuff);
		return 1;
	}

	// lets find the specified interface...if not found then for now lets just use the first one
	if(interface && strlen(interface) > 0) {
		for(device = alldevs; device; device = device->next) {
			if(!strcmp(device->name, interface)) break;
		}
		if(!device) {
			fprintf(stderr, "Interface %s is not found.\n", interface);
			pcap_freealldevs(alldevs);
			return 1;
		}
	}else {
		device = alldevs;
	}

	printf("Using device: %s\n", device->name);
	pcap_t *handle = pcap_open_live(device->name, 65536, 1, 1000, errbuff);
	if(!handle) {
		fprintf(stderr, "Could not open device: %s\n", errbuff);
		pcap_freealldevs(alldevs);
		return 1;
	}

	printf("Packet capture started. Press Ctrl + C to exit.\n");
	pcap_freealldevs(alldevs);

	struct pcap_pkthdr *header;
	const u_char *data;
	int res;

	while((res = pcap_next_ex(handle, &header, &data)) >= 0) {
		if(res == 0)continue;
		packet_handler(header, data);
	}

	pcap_close(handle);

	return 0;
}

int get_protocol_filter() {
	return protocol_filter;
}
