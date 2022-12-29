#include "raw_socket.h"
#include "config.h"

pcap_t* nic_descr;
int knockCounter;

void sniff_port_knocking() {
    int interfaces = 0;
    knockCounter = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* nic;             // interface
    struct bpf_program fp;      // holds compiled program
    bpf_u_int32 maskp;          // subnet mask
    bpf_u_int32 netp;           // ip
    u_char* args = NULL;

    // find the first NIC that is up and sniff packets from it
    interfaces = pcap_findalldevs(&nic, errbuf);
    if (interfaces == -1) {
        printf("%s\n",errbuf);
        exit(1);
    }

    // Use pcap to get the IP address and subnet mask of the device
    pcap_lookupnet (nic->name, &netp, &maskp, errbuf);

    // open the device for packet capture & set the device in promiscuous mode
    nic_descr = pcap_open_live (nic->name, BUFSIZ, 1, -1, errbuf);
    if (nic_descr == NULL) {
        fprintf(stderr,"[-]pcap_open_live(): %s\n",errbuf);
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

    fprintf(stdout,"[+]Start packet sniffing...\n\n");
    // Start the capture session
    pcap_loop (nic_descr, 0, pkt_callback, args);
}
// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    u_int caplen = pkthdr->caplen;
	struct ether_header *eptr;      /* net/ethernet.h */
	u_short ether_type;

    if (caplen < ETHER_HDRLEN)
        return;

    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    if(ether_type == ETHERTYPE_IP)  /* handle the IP packet */
        handle_IP(args,pkthdr,packet);
}

/* Parse the IP header */
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    int len;

    // Jump past the Ethernet header 
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    // make sure that the packet is of a valid length 
    if (length < sizeof(struct my_ip))
        return;

    len = ntohs(ip->ip_len);
    // Ensure that we have as much of the packet as we should 
    if (length < len)
        return;

    if(ip->ip_id == HEADERKEY) {
        switch (ip->ip_p) {
        case IPPROTO_TCP:
            handle_TCP (args, pkthdr, packet);
            break;
        case IPPROTO_UDP:
            handle_UDP (args, pkthdr, packet);
            break;
        default:
            break;
        }
    }
}

/* Parse the TCP header */
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct sniff_tcp *tcp=0;          // The TCP header 
	const struct my_ip *ip;              	// The IP header 
    const char *payload;                    // Packet payload 
    char iptables[STR_SIZE];
    memset(iptables, 0, STR_SIZE);
  	int size_ip;
    int size_tcp;
    int size_payload;
  
    ip = (struct my_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip)*4;
       
    // define/compute tcp header offset
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
        
    if (size_tcp < 20) 
        return;

    // define/compute tcp payload (segment) offset
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        
    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    int dport = tcp->th_dport;
    int sport = ntohs(tcp->th_sport);

    char dport_ch[1];
    memset(dport_ch, 0, 1);
    sprintf(dport_ch, "%c", dport);
    char sport_ch[10];
    memset(sport_ch, 0, 10);
    sprintf(sport_ch, "%d", sport);
    if (dport_ch[0] == 'k')
        knockCounter++;

    if (knockCounter == 5) {
        add_rule(inet_ntoa(ip->ip_src), sport_ch);
        knockCounter = 0;
        pcap_breakloop(nic_descr);
    }
}

/* Parse the UDP header */
void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct sniff_udp *udp=0;          // The UDP header 
	const struct my_ip *ip;              	// The IP header 
    const char *payload;                    // Packet payload 

    char iptables[STR_SIZE];
    memset(iptables, 0, STR_SIZE);
  	int size_ip;
    int size_payload;
	
    ip = (struct my_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip)*4;
       
    // define/compute udp header 
    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
    if (udp->uh_len < 8) 
        return;
    
    // define/compute udp payload 
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);   
    // compute udp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + 8);

    int dport = udp->uh_dport;
    int sport = ntohs(udp->uh_sport);
    char dport_ch[1];
    memset(dport_ch, 0, 1);
    sprintf(dport_ch, "%c", dport);
    char sport_ch[10];
    memset(sport_ch, 0, 10);
    sprintf(sport_ch, "%d", sport);
    if (dport_ch[0] == 'k')
        knockCounter++;

    if (knockCounter == 5) {
        add_rule(inet_ntoa(ip->ip_src), sport_ch);
        knockCounter = 0;
        pcap_breakloop(nic_descr);
    }
}