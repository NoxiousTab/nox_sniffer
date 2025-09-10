#include <stdio.h>
#include <string.h>
#include "capture.h"


void print_usage(const char *progname) {
	printf("Usage: %s [-i interface] [-p protocol]\n", progname);
    	printf("Options:\n");
    	printf("  -i interface   Network interface to use (e.g., eth0)\n");
    	printf("  -p protocol    Protocol filter: tcp, udp, icmp, all\n");
}


int main(int argc, char *argv[]) {
	char interface[64] = "";
	char protocol[16] = "all";

	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[i], "-i") && i + 1 < argc) {
			strncpy(interface, argv[++i], sizeof(interface) - 1);
		} else if(!strcmp(argv[i], "-p") && i + 1 < argc) {
			strncpy(protocol, argv[++i], sizeof(protocol) - 1);
		} else if(!strcmp(argv[i], "-h")) {
			print_usage(argv[0]);
			return 0;
		}
	}
	printf("Starting packet sniffer....(created by Tabish Ahmed)\n");
	printf("Interface: %s\n", interface[0] ? interface : "(default)");
	printf("Protocol: %s\n", protocol);

	if(start_capture(interface, protocol) != 0){
		fprintf(stderr, "Error starting packet capture.\n");
		return 1;
	}
	return 0;
}
