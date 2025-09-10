#include <pcap.h>
#include <stdio.h>
#include "capture.h"
#include "parser.h"



int packet_handler(struct pcap_pkthdr *header, const u_char *data) {
	parse_packet(header, data);
	return 0;
}


int start_capture() {
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	if(pcap_findalldevs(&alldevs, errbuff) == -1){
		fprintf(stderr, "Error finding devices: %s\n", errbuff);
		return 1;
	}
	// we want the first device
	pcap_if_t *device = alldevs;
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
