#include<stdio.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include"network.h"

char sendbuf[MAXBUF];
char recvbuf[MAXBUF];

in_chksum(short *pkt,int len){

        int left = len;
        unsigned int sum = 0;
        unsigned short *w = pkt;
        unsigned short answer = 0;


        while(left>1){
                sum += *w++;
                left-=2;
        }

        if(left == 1){
                *(unsigned char *)(&answer) = *(unsigned char *)w;
                sum+=answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return answer;

}

send_pkt
(int sockfd,icmp_pkt* icmp,struct sockaddr_in *target){
	int len;
	icmp = (icmp_pkt *)sendbuf;
	memset(sendbuf,'\0',sizeof(sendbuf));
	icmp->type = ECHO_REQUEST;
	icmp->code = 0;
	icmp->chksum = 0;
	icmp->id = getpid() & 0xffff;
	icmp->seq = icmp->id+1;
	memset(icmp->data,0x4a,10);
	len = 8 + 10;
#ifdef DEBUG   
	int i = 0;
	for(;i<len;i++)
		printf("sendbuf[%d]:%x\n",i,sendbuf[i]);
#endif
	icmp->chksum = in_chksum((u_short *)icmp,len);
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
(int sockfd,int pid,ipv4 *ip_dgram,icmp_pkt *icmp){
	int length,n,icmp_len;
	n = recv(sockfd,recvbuf,100,0);
	ip_dgram = (ipv4 *)recvbuf;
	length = ip_dgram->ip_hl << 2;
	if(ip_dgram->protocol != IPPROTO_ICMP)
		return;
	icmp = (icmp_pkt *)recvbuf;
	/* how to set icmp_pkt in ipv6*/
	icmp = (icmp_pkt *)(ip_dgram + length);
	if( (icmp_len = n - length) < 8)
		return;
	if(icmp->type == ECHO_REPLY){
		if(icmp->id != pid)
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
	icmp_pkt *icmp;
	ipv4 * ip_dgram;

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
	send_pkt(sockfd,icmp,&target);
	recv_pkt(sockfd,pid,ip_dgram,icmp);	
	
}


