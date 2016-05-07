#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>

#define port_targ 80		/* lets flood the sendmail port */
void PrintData (unsigned char* data , int Size);

unsigned short csum(unsigned short *addr, int len){		/* this function generates header checksums */
	unsigned long sum = 0;
	int count = len;
	unsigned short temp;

	while(count > 1){
		temp = htons(*addr++);
		sum += temp;
		count -= 2;
	}
	if(count > 0){
		sum += *(unsigned char *)addr;
	}
	while(sum>>16){
		sum = (sum & 0xffff) + (sum >> 16);
	}
	unsigned short result = ~sum;
	return result;
}

struct pseudohdr{
		struct in_addr src_addr;
		struct in_addr dest_addr;
		unsigned char reserve;
		unsigned char protocol;
		unsigned short tcp_segment_len;
};

unsigned short tcp_check(char *datagram, int len, struct in_addr src_addr, struct in_addr dest_addr){
	int tcp_load_len = 0;
	struct pseudohdr pseudohdr;
	unsigned char *pseudo_datagram;
	unsigned short result;

	pseudohdr.protocol = IPPROTO_TCP;
	pseudohdr.tcp_segment_len = htons(sizeof(struct tcphdr) + tcp_load_len);
	pseudohdr.reserve = 0;

	pseudohdr.src_addr = src_addr;
	pseudohdr.dest_addr = dest_addr;

	if((pseudo_datagram = (unsigned char *)malloc(sizeof(struct pseudohdr) + len)) == NULL){
		perror("malloc error");
		exit(1);
	}

	memcpy(pseudo_datagram, &pseudohdr, sizeof(struct pseudohdr));
	memcpy((pseudo_datagram + sizeof(pseudohdr)), datagram, len);
	PrintData ((unsigned char *)pseudo_datagram, len + sizeof(pseudohdr));
	result = htons(csum((unsigned short *)pseudo_datagram, (len + sizeof(struct pseudohdr))));
	free(pseudo_datagram);
	return result;
}

FILE *tcp_pseudo;

int
main (void)
{
  tcp_pseudo=fopen("tcp_pseudo.txt","w");
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);	/* open raw socket */
  char datagram[4096];	/* this buffer will contain ip header, tcp header,
			   and payload. we'll point an ip header structure
			   at its beginning, and a tcp header structure after
			   that to write the header values into it */
  struct ip *iph = (struct ip *) datagram;
  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
  struct sockaddr_in sin;
			/* the sockaddr_in containing the dest. address is used
			   in sendto() to determine the datagrams path */

  sin.sin_family = AF_INET;
  sin.sin_port = htons (port_targ);/* you byte-order >1byte header values to network
			      byte order (not needed on big endian machines) */
  sin.sin_addr.s_addr = inet_addr ("129.79.247.87");

  memset (datagram, 0, 4096);	/* zero out the buffer */

/* we'll now fill in the ip/tcp header values, see above for explanations */
  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 16;
  iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);	/* no payload */
  iph->ip_id = htons(54321);	/* the value doesn't matter here */
  iph->ip_off = 0;
  iph->ip_ttl = 64;
  iph->ip_p = 6;
  iph->ip_sum = 0;		/* set it to 0 before computing the actual checksum later */
  iph->ip_src.s_addr = inet_addr ("149.159.15.199");/* SYN's can be blindly spoofed */
  iph->ip_dst.s_addr = sin.sin_addr.s_addr;
  tcph->th_sport = htons (52379);	/* arbitrary port */
  tcph->th_dport = htons (port_targ);
  //tcph->th_seq = random ();/* in a SYN packet, the sequence is a random */
  tcph->th_seq = htonl(1543701112);
  tcph->th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
  tcph->th_x2 = 0;
  tcph->th_off = (unsigned short int)(sizeof(struct tcphdr)/4);		/* first and only tcp segment */
  tcph->th_flags = TH_SYN;	/* initial connection request */
  tcph->th_win = htons(29200);	/* maximum allowed window size */
  tcph->th_sum = 0;/* if you set a checksum to zero, your kernel's IP stack
		      should fill in the correct checksum during transmission */
  tcph->th_urp = 0;

  //iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len);
  tcph->th_sum = tcp_check((char *)(datagram + sizeof(struct ip)), (iph->ip_len - sizeof(struct ip)), iph->ip_src, iph->ip_dst);

/* finally, it is very advisable to do a IP_HDRINCL call, to make sure
   that the kernel knows the header is included in the data, and doesn't
   insert its own header into the packet before our data */

  {				/* lets do it the ugly way.. */
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
      printf ("Warning: Cannot set HDRINCL!\n");
  }

/* send the packet */
  {
	  if (sendto (s,		/* our socket */
		  datagram,	/* the buffer containing headers and data */
		  iph->ip_len,	/* total length of our datagram */
		  0,		/* routing flags, normally always 0 */
		  (struct sockaddr *) &sin,	/* socket addr, just like in */
		  sizeof (sin)) < 0)		/* a normal send() */
	printf ("error\n");
      else
	printf ("SYN message sent\n");
    }

  return 0;
}

void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(tcp_pseudo , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(tcp_pseudo , "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(tcp_pseudo , "."); //otherwise print a dot
            }
            fprintf(tcp_pseudo , "\n");
        }

        if(i%16==0) fprintf(tcp_pseudo , "   ");
            fprintf(tcp_pseudo , " %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(tcp_pseudo , "   "); //extra spaces
            }

            fprintf(tcp_pseudo , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  fprintf(tcp_pseudo , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(tcp_pseudo , ".");
                }
            }

            fprintf(tcp_pseudo ,  "\n" );
        }
    }
}
