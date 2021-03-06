#define MAXBUF 6500

#define MAXDATA		100

//icmp types
#define ECHO_REPLY 	0
#define ECHO_REQUEST 	8
#define DEST_UNREACH	3
#define TIME_EXC	11

//icmp destination unreachable codes
#define NET_UNREACH	0
#define HOST_UNREACH	1
#define PROTO_UNREACH	2
#define PORT_UNREACH	3
#define FRAG_NEEDED	4
#define SRCRT_FAILED	5

//return codes		
#define SUCCESS		0
#define MALFORMED	1
#define INSUFF_DATA	2
#define WRONG_PROTO	3
#define WRONG_HOST	4
#define WRONG_ID	5
#define LOW_TTL		6

typedef struct ipv4{
	unsigned char ip_hl:4,
			ip_v:4;
	unsigned char tos;
	unsigned short total_len;
	unsigned short id;
	unsigned short frag_off:13,
			flags:3;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short chksum;
	unsigned int src_addr;
	unsigned int dest_addr;
}ipv4;

typedef struct ipv6{
	unsigned int flw_lbl:20,
			trfc_class:8,
			ip_version:4;
	unsigned short payload_len;
	unsigned char nxt_hdr;
	unsigned char hop_lmt;
	unsigned char ip6_src_addr[16];
	unsigned char ip6_dst_addr[16];
	
}ipv6;

typedef struct icmp_pkt{
	unsigned char type;
	unsigned char code;
	unsigned short chksum;
	unsigned short id;
	unsigned short seq;
	char data[MAXDATA];
}icmp_pkt;
