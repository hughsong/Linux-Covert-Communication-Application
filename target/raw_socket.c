#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h> 
#include <time.h>
#include "config.h"
#include "raw_socket.h"

void forgeTCP(int ch[], char *action) {
    srand(time(0));
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(s < 0) {
        perror("[-]Socket cannot be open. Are you root?\n");
        exit(1);
    }
    // Datagram to represent the packet
	char datagram[MAX_SIZE] , *data , *pseudogram;
	
	//zero out the packet buffer
	memset (datagram, 0, MAX_SIZE);
	
	// IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	// TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_tcp pst;
	
	// Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcat(data, " ");
	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(CLIENTPORT);
	sin.sin_addr.s_addr = inet_addr(CLIENTIP);
	
	// Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph->id = HEADERKEY;	// Id of this packet
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		// Set to 0 before calculating checksum
	iph->daddr = sin.sin_addr.s_addr;
	iph->saddr = inet_addr(TARGETIP);
	// Ip checksum
	iph->check = in_cksum((unsigned short *) datagram, iph->tot_len);
	
	if(strcmp("knock", action)==0) {
        tcph->dest = ch[0];
		tcph->source = htons(KNOCK);
		tcph->seq = 1+(int)(10000.0*rand()/(RAND_MAX+1.0));
		tcph->ack_seq = 0;
		tcph->window = htons(MAX_SIZE);
    } else {
        tcph->dest = htons(KNOCK);
        tcph->source = ch[0];
		tcph->seq = ch[1];
		tcph->ack_seq = ch[2];
		tcph->window = ch[3];
	}
	// TCP Header
	tcph->doff = 5;	// tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->check = 0;
	tcph->urg_ptr = 0;

	// TCP checksum
	pst.source_address = inet_addr(TARGETIP);
	pst.dest_address = sin.sin_addr.s_addr;
	pst.placeholder = 0;
	pst.protocol = IPPROTO_TCP;
	pst.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));
	
	int psize = sizeof(struct pseudo_tcp) + sizeof(struct tcphdr) + strlen(data);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &pst , sizeof (struct pseudo_tcp));
	memcpy(pseudogram + sizeof(struct pseudo_tcp) , tcph , sizeof(struct tcphdr) + strlen(data));
	
	tcph->check = in_cksum( (unsigned short*) pseudogram , psize);

    if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin))< 0)
		perror("[-]ERROR: Fail sending packet!\n");
    else
        printf ("Packet Sent. Length : %d \n" , iph->tot_len);

    close(s);
}


void forgeUDP(int ch[], char *action) {
    srand(time(0));
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(s < 0) {
        perror("[-]Socket cannot be open. Are you root?\n");
        exit(1);
    }
	// Datagram to represent the packet
	char datagram[MAX_SIZE], *data , *pseudogram;
	// Zero out the packet buffer
	memset (datagram, 0, MAX_SIZE);
	struct iphdr *iph = (struct iphdr *) datagram;
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_udp psu;
	// Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcat(data, " ");

	sin.sin_family = AF_INET;
    sin.sin_port = htons(CLIENTPORT);
    sin.sin_addr.s_addr = inet_addr(CLIENTIP);

	// Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = HEADERKEY;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;		            //Set to 0 before calculating checksum
	iph->daddr = sin.sin_addr.s_addr;
	iph->saddr = inet_addr(TARGETIP);
	
	// Ip checksum
	iph->check = in_cksum ((unsigned short *) datagram, iph->tot_len);

    if(strcmp("knock", action)==0) {
        udph->dest = ch[0];
		udph->source = htons(KNOCK);
    } else {
        udph->dest = htons(KNOCK);
        udph->source = ch[0];
	}

	// UDP header
	udph->len = htons(8 + strlen(data));	//udp header size
	udph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	
	// UDP checksum
	psu.source_address = inet_addr(TARGETIP);
	psu.dest_address = sin.sin_addr.s_addr;
	psu.placeholder = 0;
	psu.protocol = IPPROTO_UDP;
	psu.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
	
	int psize = sizeof(struct pseudo_udp) + sizeof(struct udphdr) + strlen(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram , (char*) &psu , sizeof (struct pseudo_udp));
	memcpy(pseudogram + sizeof(struct pseudo_udp) , udph , sizeof(struct udphdr) + strlen(data));
	
	udph->check = in_cksum( (unsigned short*) pseudogram , psize);
	
	if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin))< 0)
		perror("[-]ERROR: Fail sending packet!\n");
    else
        printf ("Packet Sent. Length : %d \n" , iph->tot_len);

    close(s);
}


unsigned short in_cksum(unsigned short *ptr, int nbytes) {
	register long	    sum;                    /* assumes long == 32 bits */
	u_short			    oddbyte;
	register u_short	answer;		            /* assumes u_short == 16 bits */

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;		                    /* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;/* one byte only */
		sum += oddbyte;
	}

	sum  = (sum >> 16) + (sum & 0xffff);        /* add high-16 to low-16 */
	sum += (sum >> 16);			                /* add carry */
	answer = ~sum;		                        /* ones-complement, then truncate to 16 bits */
	return(answer);
} 
