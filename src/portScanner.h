#ifndef PORTSCANNER_H_
#define PORTSCANNER_H_

#include <iostream>
#include <set>
#include <string>
#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>

#define OPEN 0x01;
#define CLOSED 0x02;
#define FILTERED 0x03;
#define UNFILTERED 0x04;
#define OPENFILTERED 0x05;

struct pseudohdr{				//pseudo-header for TCP header's checksum's computation
	struct in_addr src_addr;
	struct in_addr dest_addr;
	unsigned char reserve;
	unsigned char protocol;
	unsigned short tcp_segment_len;
};

typedef	u_int32_t tcp_seq;
/*
 *  * TCP header.
 *   * Per RFC 793, September, 1981.
 *    */
struct tcphdr
  {
    __extension__ union
    {
      struct
      {
	u_int16_t th_sport;		/* source port */
	u_int16_t th_dport;		/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t th_x2:4;		/* (unused) */
	u_int8_t th_off:4;		/* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t th_off:4;		/* data offset */
	u_int8_t th_x2:4;		/* (unused) */
# endif
	u_int8_t th_flags;
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
	u_int16_t th_win;		/* window */
	u_int16_t th_sum;		/* checksum */
	u_int16_t th_urp;		/* urgent pointer */
      };
      struct
      {
	u_int16_t source;
	u_int16_t dest;
	u_int32_t seq;
	u_int32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int16_t res1:4;
	u_int16_t doff:4;
	u_int16_t fin:1;
	u_int16_t syn:1;
	u_int16_t rst:1;
	u_int16_t psh:1;
	u_int16_t ack:1;
	u_int16_t urg:1;
	u_int16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
	u_int16_t doff:4;
	u_int16_t res1:4;
	u_int16_t res2:2;
	u_int16_t urg:1;
	u_int16_t ack:1;
	u_int16_t psh:1;
	u_int16_t rst:1;
	u_int16_t syn:1;
	u_int16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
	u_int16_t window;
	u_int16_t check;
	u_int16_t urg_ptr;
      };
    };
};

struct request_tuple{
	char request_ip[20];
	int request_port;
	int th_process;
	char state_SYN;
	char state_NULL;
	char state_FIN;
	char state_Xmas;
	char state_ACK;
	char state_UDP;
	char state_concluion;
	char service_type[50];
	char service_version[20];
	int service_verified;
};

struct tcp_state{
	int RST;
	int ACK;
	int SYN;
};

struct icmp_state{
	int type;
	int code;
};

class PortScanner {
public:
	std::set<int> request_ports;
	std::set<std::string> request_ip;
	std::set<std::string> request_scan_flag;
	int num_req;
	struct request_tuple *table_req;
	int num_done_req;
	int num_next_req;
	int check_all;
	pthread_mutex_t mutex1;
	//pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

	char local_ip[20];
	int speed_up;
	PortScanner(); //construction function
	static unsigned short csum(unsigned short *addr, int len); //general function used to compute the checksum for ip and tcp header
	static unsigned short tcpCheck(char *datagram, int len, struct in_addr src_addr, struct in_addr dest_addr); //compute TCP checksum using TCP_pseudo_header + TCP_segment
	static int getSrcIp(unsigned char* buffer, char *src_ip, int *src_port); //inspect the protocol type of incoming message, if tcp/udp get ip and port
	static int checkViaSYN(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim);
	static int checkViaNULL(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim);
	static int checkViaFIN(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim);
	static int checkViaXmas(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim);
	static int checkViaACK(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim);
	static int checkViaUDP(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim);
	static int checkService(unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim);
	/*during a 3s period, continuously check if the recv msg match the desired ip/port, if match, then return 0 and the data will be saved in "buffer" for length "data_size"*/
	static int recvMatch(int sock_num, unsigned char* buffer, int *data_size, int *type, char *ip_targ, int port_targ); //return 0 if match found, return 1 if didn't found, return -1 if fail to recvfrom socket, use type to save msg protocol type
	static int prcTCP(unsigned char *buffer, int data_size, struct tcp_state *tcp_result);
	static int prcICMP(unsigned char *buffer, int data_size, struct icmp_state *icmp_result);
	static int sendSYN(const char *dst_ip, int dst_port, PortScanner *ps, int socket);
	static int sendFIN(const char *dst_ip, int dst_port, PortScanner *ps, int socket);
	static int sendACK(const char *dst_ip, int dst_port, PortScanner *ps, int socket);
	static int sendUDP(const char *dst_ip, int dst_port, PortScanner *ps, int socket);
	static int sendNULL(const char *dst_ip, int dst_port, PortScanner *ps, int socket);
	static int sendXmas(const char *dst_ip, int dst_port, PortScanner *ps, int socket);
	static void readSock(int client_sock, void *buffer, int size);
	static void getServiceName(int port, char *name);
	static void stateConclude(PortScanner *ps, int request_id);


	int getLocalIP();
	int initRequestTable();
	void forgeRequestTable();
};

struct multith_feed{
	int th_id;
	PortScanner *ps_addr;
	bool TCP_SYN;
	bool TCP_NULL;
	bool TCP_FIN;
	bool TCP_Xmas;
	bool TCP_ACK;
	bool UDP;
};

#endif /* PORTSCANNER_H_ */
