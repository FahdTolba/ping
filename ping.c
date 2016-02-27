#include<stdio.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include"arsenal.h"

#define MAXBUF 6500
#define ECHO_REPLY   0
#define ECHO_REQUEST 8

char sendbuf[MAXBUF];
char recvbuf[MAXBUF];

typedef struct _ip{
	unsigned char ip_hl:4,
			ip_v:4;
	unsigned char tos;
	unsigned short total_len;
	unsigned short id;
	unsigned short frag_off:13,
			flags:3;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int src_addr;
	unsigned int dest_addr;
}ip;

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

typedef struct _icmp{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
	char data[100];
}icmp;

send_pkt
(int sockfd,icmp* icmp_pkt,struct sockaddr_in *target){
	int len;
	icmp_pkt = (icmp *)sendbuf;
	memset(sendbuf,'\0',sizeof(sendbuf));
	icmp_pkt->type = ECHO_REQUEST;
	icmp_pkt->code = 0;
	icmp_pkt->checksum = 0;
	icmp_pkt->id = getpid() & 0xffff;
	icmp_pkt->seq = icmp_pkt->id+1;
	memset(icmp_pkt->data,0x4a,10);
	len = 8 + 10;
#ifdef DEBUG   
	int i = 0;
	for(;i<len;i++)
		printf("sendbuf[%d]:%x\n",i,sendbuf[i]);
#endif
	icmp_pkt->checksum = in_chksum((u_short *)icmp_pkt,len);
#ifdef DEBUG
	i = 0;
	for(i=0;i<len;i++)
	printf("sendbuf[%d]:%x\n",i,sendbuf[i]);
#endif
	sendto(sockfd,sendbuf,len,0,
		(struct sockaddr *)target,
		sizeof(*target));
}

recv_pkt
(int sockfd,int pid,ip *ip_dgram,icmp *icmp_pkt){
	int length,n,icmp_len;
	n = recv(sockfd,recvbuf,100,0);
	ip_dgram = (ip *)recvbuf;
	length = ip_dgram->ip_hl << 2;
	if(ip_dgram->protocol != IPPROTO_ICMP)
		return;
	icmp_pkt = (icmp *)recvbuf;
	/* how to set icmp_pkt in ipv6*/
	icmp_pkt = (icmp *)(ip_dgram + length);
	if( (icmp_len = n - length) < 8)
		return;
	if(icmp_pkt->type == ECHO_REPLY){
		if(icmp_pkt->id != pid)
			return;
		if( icmp_len  < 16)
			return;
		//print the source of echo reply
		unsigned int reply_src = ntohl(ip_dgram->src_addr);
		unsigned int reply_dest = ntohl(ip_dgram->dest_addr);
		printf("received icmp echo reply from %d.%d.%d.%d\n",
				(reply_src>>24) & 0xff,
				(reply_src>>16) & 0xff,
				(reply_src>>8) & 0xff,
				reply_src & 0xff);

		//print the dest of echo reply
		printf("received icmp echo reply destined to %d.%d.%d.%d\n",
				(reply_dest>>24) & 0xff,
				(reply_dest>>16) & 0xff,
				(reply_dest>>8) & 0xff,
				reply_dest & 0xff);
		printf("ttl = %d\n",ip_dgram->ttl & 0xff);
	}
}

main(int argc,char *argv[]){

	int sockfd,pid;
	icmp *icmp_pkt;
	ip * ip_dgram;

	struct sockaddr_in target,replyaddr;
	sockfd = socket(AF_INET,SOCK_RAW,
			#ifdef IPv6 
				IPPROTO_ICMPv6
			#else
				IPPROTO_ICMP
			#endif
				);

	target.sin_family = AF_INET;
	target.sin_addr.s_addr = inet_addr(argv[1]);
	memset(target.sin_zero,'\0',8);
	send_pkt(sockfd,icmp_pkt,&target);
	recv_pkt(sockfd,pid,ip_dgram,icmp_pkt);	
	
}


