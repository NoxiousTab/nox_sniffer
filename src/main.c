#include <stdio.h>
#include "capture.h"

int main() {
	printf("Starting packet sniffer....(created by Tabish Ahmed)\n");
	if(start_capture() != 0){
		fprintf(stderr, "Error starting packet capture.\n");
		return 1;
	}
	return 0;
}
