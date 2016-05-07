#include "portScanner.h"

PortScanner::PortScanner(){
	this->speed_up = 1;
	this->num_req = 0;
	this->table_req = NULL;
	this->num_done_req = 0;
	this->num_next_req = 0;
	this->check_all = 0;
	this->mutex1 = PTHREAD_MUTEX_INITIALIZER;
}

unsigned short PortScanner::csum(unsigned short *addr, int len){		/* this function generates header checksums */
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

unsigned short PortScanner::tcpCheck(char *datagram, int len, struct in_addr src_addr, struct in_addr dest_addr){
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
	result = htons(csum((unsigned short *)pseudo_datagram, (len + sizeof(struct pseudohdr))));
	free(pseudo_datagram);
	return result;
}

int PortScanner::sendSYN(const char *dst_ip, int dst_port, PortScanner *ps, int socket){
	char datagram[256];
	struct ip *iph = (struct ip *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons (dst_port);/* you byte-order >1byte header values to network
				      byte order (not needed on big endian machines) */
	sin.sin_addr.s_addr = inet_addr (dst_ip);

	memset (datagram, 0, 256);	/* zero out the buffer */

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
	iph->ip_src.s_addr = inet_addr (ps->local_ip);/* SYN's can be blindly spoofed */
	iph->ip_dst.s_addr = sin.sin_addr.s_addr;
	tcph->th_sport = htons (52379);	/* arbitrary port */
	tcph->th_dport = htons (dst_port);
	tcph->th_seq = random ();/* in a SYN packet, the sequence is a random */
	tcph->th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
	tcph->th_x2 = 0;
	tcph->th_off = (unsigned short int)(sizeof(struct tcphdr)/4);		/* first and only tcp segment */
	tcph->th_flags = TH_SYN;	/* initial connection request */
	tcph->th_win = htons(29200);
	tcph->th_sum = 0;
	tcph->th_urp = 0;

	tcph->th_sum = PortScanner::tcpCheck((char *)(datagram + sizeof(struct ip)), (iph->ip_len - sizeof(struct ip)), iph->ip_src, iph->ip_dst);

	/* send the packet */
	{
		if (sendto (socket,			/* socket */
					datagram,	/* the buffer containing headers and data */
					iph->ip_len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &sin,	/* socket addr, just like in */
					sizeof (sin)) < 0){			/* a normal send() */
			printf ("send SYN error\n");
		}
		else{
			printf ("SYN message sent\n");
		}
	}
	return 0;
}

int PortScanner::sendFIN(const char *dst_ip, int dst_port, PortScanner *ps, int socket){
	char datagram[256];
	struct ip *iph = (struct ip *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons (dst_port);/* you byte-order >1byte header values to network
				      byte order (not needed on big endian machines) */
	sin.sin_addr.s_addr = inet_addr (dst_ip);

	memset (datagram, 0, 256);	/* zero out the buffer */

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
	iph->ip_src.s_addr = inet_addr (ps->local_ip);/* SYN's can be blindly spoofed */
	iph->ip_dst.s_addr = sin.sin_addr.s_addr;
	tcph->th_sport = htons (52379);	/* arbitrary port */
	tcph->th_dport = htons (dst_port);
	tcph->th_seq = random ();
	tcph->th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
	tcph->th_x2 = 0;
	tcph->th_off = (unsigned short int)(sizeof(struct tcphdr)/4);		/* first and only tcp segment */
	tcph->th_flags = TH_FIN;	/* initial connection request */
	tcph->th_win = htons(29200);
	tcph->th_sum = 0;
	tcph->th_urp = 0;

	tcph->th_sum = PortScanner::tcpCheck((char *)(datagram + sizeof(struct ip)), (iph->ip_len - sizeof(struct ip)), iph->ip_src, iph->ip_dst);

	/* send the packet */
	{
		if (sendto (socket,			/* socket */
					datagram,	/* the buffer containing headers and data */
					iph->ip_len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &sin,	/* socket addr, just like in */
					sizeof (sin)) < 0){			/* a normal send() */
			printf ("send FIN error\n");
		}
		else{
			printf ("FIN message sent\n");
		}
	}
	return 0;
}

int PortScanner::sendNULL(const char *dst_ip, int dst_port, PortScanner *ps, int socket){
	char datagram[256];
	struct ip *iph = (struct ip *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons (dst_port);/* you byte-order >1byte header values to network
				      byte order (not needed on big endian machines) */
	sin.sin_addr.s_addr = inet_addr (dst_ip);

	memset (datagram, 0, 256);	/* zero out the buffer */

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
	iph->ip_src.s_addr = inet_addr (ps->local_ip);
	iph->ip_dst.s_addr = sin.sin_addr.s_addr;
	tcph->th_sport = htons (52379);	/* arbitrary port */
	tcph->th_dport = htons (dst_port);
	tcph->th_seq = random ();
	tcph->th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
	tcph->th_x2 = 0;
	tcph->th_off = (unsigned short int)(sizeof(struct tcphdr)/4);		/* first and only tcp segment */
	tcph->th_flags = 0x00;	/* initial connection request */
	tcph->th_win = htons(29200);
	tcph->th_sum = 0;
	tcph->th_urp = 0;

	tcph->th_sum = PortScanner::tcpCheck((char *)(datagram + sizeof(struct ip)), (iph->ip_len - sizeof(struct ip)), iph->ip_src, iph->ip_dst);

	/* send the packet */
	{
		if (sendto (socket,			/* socket */
					datagram,	/* the buffer containing headers and data */
					iph->ip_len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &sin,	/* socket addr, just like in */
					sizeof (sin)) < 0){			/* a normal send() */
			printf ("send NULL error\n");
		}
		else{
			printf ("NULL message sent\n");
		}
	}
	return 0;
}

int PortScanner::sendXmas(const char *dst_ip, int dst_port, PortScanner *ps, int socket){
	char datagram[256];
	struct ip *iph = (struct ip *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons (dst_port);/* you byte-order >1byte header values to network
				      byte order (not needed on big endian machines) */
	sin.sin_addr.s_addr = inet_addr (dst_ip);

	memset (datagram, 0, 256);	/* zero out the buffer */

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
	iph->ip_src.s_addr = inet_addr (ps->local_ip);
	iph->ip_dst.s_addr = sin.sin_addr.s_addr;
	tcph->th_sport = htons (52379);	/* arbitrary port */
	tcph->th_dport = htons (dst_port);
	tcph->th_seq = random ();
	tcph->th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
	tcph->th_x2 = 0;
	tcph->th_off = (unsigned short int)(sizeof(struct tcphdr)/4);		/* first and only tcp segment */
	tcph->th_flags = 0x29;	/* initial connection request */
	tcph->th_win = htons(29200);
	tcph->th_sum = 0;
	tcph->th_urp = 0;

	tcph->th_sum = PortScanner::tcpCheck((char *)(datagram + sizeof(struct ip)), (iph->ip_len - sizeof(struct ip)), iph->ip_src, iph->ip_dst);

	/* send the packet */
	{
		if (sendto (socket,			/* socket */
					datagram,	/* the buffer containing headers and data */
					iph->ip_len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &sin,	/* socket addr, just like in */
					sizeof (sin)) < 0){			/* a normal send() */
			printf ("send Xmas error\n");
		}
		else{
			printf ("Xmas message sent\n");
		}
	}
	return 0;
}

int PortScanner::sendACK(const char *dst_ip, int dst_port, PortScanner *ps, int socket){
	char datagram[256];
	struct ip *iph = (struct ip *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons (dst_port);/* you byte-order >1byte header values to network
				      byte order (not needed on big endian machines) */
	sin.sin_addr.s_addr = inet_addr (dst_ip);

	memset (datagram, 0, 256);	/* zero out the buffer */

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
	iph->ip_src.s_addr = inet_addr (ps->local_ip);/* SYN's can be blindly spoofed */
	iph->ip_dst.s_addr = sin.sin_addr.s_addr;

	tcph->th_sport = htons (52379);	/* arbitrary port */
	tcph->th_dport = htons (dst_port);
	tcph->th_seq = random ();
	tcph->th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
	tcph->th_x2 = 0;
	tcph->th_off = (unsigned short int)(sizeof(struct tcphdr)/4);		/* first and only tcp segment */
	tcph->th_flags = TH_ACK;	/* initial connection request */
	tcph->th_win = htons(29200);
	tcph->th_sum = 0;
	tcph->th_urp = 0;

	tcph->th_sum = PortScanner::tcpCheck((char *)(datagram + sizeof(struct ip)), (iph->ip_len - sizeof(struct ip)), iph->ip_src, iph->ip_dst);

	/* send the packet */
	{
		if (sendto (socket,			/* socket */
					datagram,	/* the buffer containing headers and data */
					iph->ip_len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &sin,	/* socket addr, just like in */
					sizeof (sin)) < 0){			/* a normal send() */
			printf ("send ACK error\n");
		}
		else{
			printf ("ACK message sent\n");
		}
	}
	return 0;
}

int PortScanner::sendUDP(const char *dst_ip, int dst_port, PortScanner *ps, int socket){
	if(dst_port == 53){
		char datagram[256];
		memset(datagram, 0, 256);
		struct ip *iph = (struct ip *) datagram;
		struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
		char dns_payload[12];
		struct sockaddr_in sin;

		sin.sin_family = AF_INET;
		sin.sin_port = htons (dst_port);
		sin.sin_addr.s_addr = inet_addr (dst_ip);

		iph->ip_hl = 5;
		iph->ip_v = 4;
		iph->ip_tos = 0;
		iph->ip_len = sizeof (struct ip) + sizeof (struct udphdr) + 12;
		iph->ip_id = htons(54321);	/* the value doesn't matter here */
		iph->ip_off = 0;
		iph->ip_ttl = 128;
		iph->ip_p = 17;
		iph->ip_sum = 0;
		iph->ip_src.s_addr = inet_addr (ps->local_ip);
		iph->ip_dst.s_addr = sin.sin_addr.s_addr;

		udph->source = htons (52379);
		udph->dest = htons (dst_port);
		udph->check = 0;
		udph->len = htons(20);

		memset(dns_payload, 0, 12);
		dns_payload[2] = 16;
		memcpy(datagram + sizeof(struct ip) + sizeof(struct udphdr), dns_payload, 12);

		/* send the packet */
		{
			if (sendto (socket,			/* socket */
					datagram,	/* the buffer containing headers and data */
					iph->ip_len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &sin,	/* socket addr, just like in */
					sizeof (sin)) < 0){			/* a normal send() */
					printf ("send UDP(DNS) error\n");
				}
			else{
				printf ("UDP(DNS) message sent\n");
			}
		}
	}
	else{
		char datagram[256];
		memset(datagram, 0, 256);
		struct ip *iph = (struct ip *) datagram;
		struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
		struct sockaddr_in sin;

		sin.sin_family = AF_INET;
		sin.sin_port = htons (dst_port);
		sin.sin_addr.s_addr = inet_addr (dst_ip);

		iph->ip_hl = 5;
		iph->ip_v = 4;
		iph->ip_tos = 0;
		iph->ip_len = sizeof (struct ip) + sizeof (struct udphdr);
		iph->ip_id = htons(54321);	/* the value doesn't matter here */
		iph->ip_off = 0;
		iph->ip_ttl = 128;
		iph->ip_p = 17;
		iph->ip_sum = 0;
		iph->ip_src.s_addr = inet_addr (ps->local_ip);
		iph->ip_dst.s_addr = sin.sin_addr.s_addr;

		udph->source = htons (52379);
		udph->dest = htons (dst_port);
		udph->check = 0;
		udph->len = htons(8);

		/* send the packet */
		{
			if (sendto (socket,			/* socket */
					datagram,	/* the buffer containing headers and data */
					iph->ip_len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &sin,	/* socket addr, just like in */
					sizeof (sin)) < 0){			/* a normal send() */
					printf ("send UDP error\n");
				}
			else{
				printf ("UDP message sent\n");
			}
		\
		}

	}
	return 0;
}

int PortScanner::getLocalIP(){
	memset(this->local_ip, 0, 20);
	struct ifaddrs * ifAddrStruct=NULL;
	struct ifaddrs * ifa=NULL;
	void * tmpAddrPtr=NULL;

	getifaddrs(&ifAddrStruct);

	for(ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) {
			continue;
	    }
	    if(ifa->ifa_addr->sa_family == AF_INET) { // check if it is IP4
	    	tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
	        char addressBuffer[INET_ADDRSTRLEN];
	        inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
	        if(strcmp(ifa->ifa_name, "eth0") == 0){
	        	strcpy(this->local_ip, addressBuffer);
	        }
	    }
	}
	if (ifAddrStruct!=NULL){
		freeifaddrs(ifAddrStruct);
	}
	//std::cout << this->local_ip << std::endl;
	return 0;
}

int PortScanner::getSrcIp(unsigned char* buffer, char *src_ip, int *src_port){ //inspect the protocol type of incoming message, if tcp/udp get ip and port
	memset(src_ip, 0, INET_ADDRSTRLEN);
	*src_port = 0;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	unsigned short iphdrlen;
	iphdrlen = iph->ihl*4;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct sockaddr_in str_addr;
	memset(&str_addr, 0, sizeof(str_addr));

	switch (iph->protocol){
	 	 case 1:  //ICMP Protocol
	 		 iph = (struct iphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
	 		 str_addr.sin_addr.s_addr = iph->daddr;
	 		 strcpy(src_ip, inet_ntoa(str_addr.sin_addr));
	 		 if(iph->protocol == 6){
	 			 tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct iphdr));
	 			 *src_port = ntohs(tcph->dest);
	 		 }
	 		 else if(iph->protocol == 17){
	 			 udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct iphdr));
	 			 *src_port = ntohs(udph->dest);
	 		 }

	 		 return 1;

	     case 6:  //TCP Protocol
	    	 str_addr.sin_addr.s_addr = iph->saddr;
	    	 strcpy(src_ip, inet_ntoa(str_addr.sin_addr));
	    	 tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	    	 *src_port = ntohs(tcph->source);
	    	 return 6;

	     case 17: //UDP Protocol
	    	 str_addr.sin_addr.s_addr = iph->saddr;
	    	 strcpy(src_ip, inet_ntoa(str_addr.sin_addr));
	    	 udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
	    	 *src_port = ntohs(udph->source);
	    	 return 17;

	     default: //Some Other Protocol like ARP etc.
	         return -1;
	}
}

int PortScanner::recvMatch(int sock, unsigned char *buffer, int *data_size, int *type, char *ip_targ, int port_targ){
	int saddr_size;
	char src_ip[INET_ADDRSTRLEN];
	int src_port;
	struct sockaddr_in saddr;
	saddr_size = sizeof saddr;
	clock_t start = clock();
	while((clock() - start)/CLOCKS_PER_SEC < 3){

		*data_size = recvfrom(sock , buffer , 65536 , 0 , (struct sockaddr *)&saddr , (socklen_t*)&saddr_size);
		//printf("data_size received: %d\n", *data_size);
		if(*data_size == -1){
			continue;
		}
		*type = PortScanner::getSrcIp(buffer, src_ip, &src_port);
		//printf("recv from ip: %s, port: %d\n", src_ip, src_port);
		if(*type > 0){
			if(strcmp(src_ip, ip_targ) == 0 && src_port == port_targ){
				return 0;
			}
		}
	}
	return 1;
}

int PortScanner::prcTCP(unsigned char *buffer, int data_size, struct tcp_state *tcp_result){
	tcp_result->ACK = 0;
	tcp_result->RST = 0;
	tcp_result->SYN = 0;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	int iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	tcp_result->ACK = (unsigned int)tcph->ack;
	tcp_result->RST = (unsigned int)tcph->rst;
	tcp_result->SYN = (unsigned int)tcph->syn;
	return 0;
}

int PortScanner::prcICMP(unsigned char *buffer, int data_size, struct icmp_state *icmp_result){
	icmp_result->code = 0;
	icmp_result->type = 0;
	struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	int iphdrlen = iph->ihl * 4;
	struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));
	icmp_result->code = icmph->code;
	icmp_result->type = icmph->type;
	return 0;
}

int PortScanner::initRequestTable(){
	this->table_req = (struct request_tuple *)malloc(sizeof(struct request_tuple) * this->num_req);
	if(!this->table_req){
		printf("ERROR: fail to malloc for request table\n");
		return 1;
	}
	memset(this->table_req, 0, sizeof(struct request_tuple)*this->num_req);
	return 0;
}

void PortScanner::forgeRequestTable(){
	int num = 0;
	if(this->request_scan_flag.size() == 0){
		this->check_all = 1;
	}
	for(std::set<std::string>::iterator it = this->request_ip.begin(); it != this->request_ip.end(); ++it){
		for(std::set<int>::iterator iti = this->request_ports.begin(); iti != this->request_ports.end(); ++iti){
			std::string ip = *it;
			int port = *iti;
			table_req[num].request_port = port;
			strcpy(table_req[num].request_ip, ip.c_str());
			table_req[num].state_ACK = 0;
			table_req[num].state_FIN = 0;
			table_req[num].state_NULL = 0;
			table_req[num].state_SYN = 0;
			table_req[num].state_UDP = 0;
			table_req[num].state_Xmas = 0;
			memset(table_req[num].service_type, 0, 50);
			memset(table_req[num].service_version, 0, 20);
			table_req[num].service_verified = 0;
			num++;
		}
	}
}

void PortScanner::readSock(int client_sock, void *buffer, int size){
	int wait = 2 * CLOCKS_PER_SEC;
	clock_t start = clock();
	clock_t now;
	char *writePoint = (char *)buffer;
	int sizeLeft = size;
	int readNum = 0;
	while(readNum < sizeLeft && wait > 0){
		sizeLeft = sizeLeft - readNum;
		writePoint = writePoint + readNum;
		readNum = recv(client_sock, writePoint, sizeLeft, 0);
		now = clock();
		wait = wait - (now - start) * CLOCKS_PER_SEC;
		printf("wait: %d\n", wait);
	}
	return;
}

void PortScanner::getServiceName(int port, char *name){
	if(port < 0 || port > 1024){
		return;
	}
	char port_name[10];
	memset(port_name, 0, 10);
	snprintf(port_name, 10, "%d", port);
	struct addrinfo *ai;
	getaddrinfo(0, port_name, 0, &ai);
	getnameinfo(ai->ai_addr, ai->ai_addrlen, 0, 0, name, sizeof(name), 0);
	freeaddrinfo(ai);
}

void PortScanner::stateConclude(PortScanner *ps, int request_id){
	if(ps->table_req[request_id].state_SYN != 0){
		ps->table_req[request_id].state_concluion = ps->table_req[request_id].state_SYN;
		return;
	}
	if(ps->table_req[request_id].state_ACK != 0){
		ps->table_req[request_id].state_concluion = ps->table_req[request_id].state_ACK;
		return;
	}
	if(ps->table_req[request_id].state_NULL != 0){
		ps->table_req[request_id].state_concluion = ps->table_req[request_id].state_NULL;
		return;
	}
	if(ps->table_req[request_id].state_FIN != 0){
		ps->table_req[request_id].state_concluion = ps->table_req[request_id].state_FIN;
		return;
	}
	if(ps->table_req[request_id].state_Xmas != 0){
		ps->table_req[request_id].state_concluion = ps->table_req[request_id].state_Xmas;
		return;
	}
	if(ps->table_req[request_id].state_UDP != 0){
		ps->table_req[request_id].state_concluion = ps->table_req[request_id].state_UDP;
		return;
	}
	ps->table_req[request_id].state_concluion = 0;
	return;
}
