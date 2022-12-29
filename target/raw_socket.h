#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h> 
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h> 
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h> 
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <ctype.h>

#define SIZE_ETHERNET 14
#ifndef ETHER_HDRLEN // tcpdump header (ether.h) defines ETHER_HDRLEN) 
#define ETHER_HDRLEN 14
#endif

// Function Prototypes
void pkt_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_TCP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_UDP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void forgeTCP(int ch[], char *action);
void forgeUDP(int ch[], char *action);
void process_command(char *cmd);
void delete_file(char* file);
void* Thread_send(void* file);
void* Thread_inot(void* cmd);
int msleep(long msec);
int inot (char* dir, char* file);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
void encryptDecrypt(char outString[], const char inpString[], char xorKey[]);

/* Structure of an UDP raw socket header */
struct pseudo_udp
{
	u_int32_t   source_address;
	u_int32_t   dest_address;
	u_int8_t    placeholder;
	u_int8_t    protocol;
	u_int16_t   udp_length;
};

/* Structure of an TCP raw socket header */
struct pseudo_tcp
{
        u_int32_t   source_address;
        u_int32_t   dest_address;
        u_int8_t    placeholder;
        u_int8_t    protocol;
        u_int16_t   tcp_length;
};

/*
 * Structure of an internet header, stripped of all options.
 *
 * This is taken directly from the tcpdump source
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct my_ip 
{
	u_int8_t	ip_vhl;		            /* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		            /* type of service */
	u_int16_t	ip_len;		            /* total length */
	u_int16_t	ip_id;		            /* identification */
	u_int16_t	ip_off;		            /* fragment offset field */
#define	IP_DF 0x4000		                    /* dont fragment flag */
#define	IP_MF 0x2000		                    /* more fragments flag */
#define	IP_OFFMASK 0x1fff	                    /* mask for fragmenting bits */
	u_int8_t	ip_ttl;		            /* time to live */
	u_int8_t	ip_p;		            /* protocol */
	u_int16_t	ip_sum;		            /* checksum */
	struct	in_addr ip_src,ip_dst;	            /* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp 
{
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct sniff_udp 
{
        u_short   uh_sport;             /* source port */
        u_short   uh_dport;             /* destination port */
        u_int16_t uh_len;		/* total length */
        u_short   uh_sum;               /* checksum */
};

