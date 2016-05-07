#include "portScanner.h"

int PortScanner::checkViaSYN(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim){
	memset(buffer, 0, sizeof(buffer));
	int try_remain = 3;
	struct icmp_state icmp_result;
	struct tcp_state tcp_result;
	int data_size = 0;
	int type;

	while(try_remain > 0){
		PortScanner::sendSYN(ip_victim, port_victim, ps, sock_send);
		int match_result = PortScanner::recvMatch(sock_recv, buffer, &data_size, &type, ip_victim, port_victim);
		if(match_result == 1){
			try_remain--;
			continue;
		}
		if(match_result == 0){
			if(type == 1){
				PortScanner::prcICMP(buffer, data_size, &icmp_result);
				int code = icmp_result.code;
				if(icmp_result.type == 3 && (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13)){
					ps->table_req[request_id].state_SYN = FILTERED;
					return 0;
				}
			}
			else if(type == 6){
				PortScanner::prcTCP(buffer, data_size, &tcp_result);
				if(tcp_result.SYN == 1){
					ps->table_req[request_id].state_SYN = OPEN;
				}
				else if(tcp_result.RST == 1){
					ps->table_req[request_id].state_SYN = CLOSED;
				}
				return 0;
			}
		}
	}
	ps->table_req[request_id].state_SYN = FILTERED;
	return 0;
}

int PortScanner::checkViaNULL(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim){
	memset(buffer, 0, sizeof(buffer));
	int try_remain = 3;
	struct icmp_state icmp_result;
	struct tcp_state tcp_result;
	int data_size = 0;
	int type;

	while(try_remain > 0){
		PortScanner::sendNULL(ip_victim, port_victim, ps, sock_send);
		int match_result = PortScanner::recvMatch(sock_recv, buffer, &data_size, &type, ip_victim, port_victim);
		if(match_result == 1){
			try_remain--;
			continue;
		}
		if(match_result == 0){
			if(type == 1){
				PortScanner::prcICMP(buffer, data_size, &icmp_result);
				int code = icmp_result.code;
				if(icmp_result.type == 3 && (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13)){
					ps->table_req[request_id].state_NULL = FILTERED;
					return 0;
				}
			}
			else if(type == 6){
				PortScanner::prcTCP(buffer, data_size, &tcp_result);
				if(tcp_result.RST == 1){
					ps->table_req[request_id].state_NULL = CLOSED;
					return 0;
				}
			}
		}
	}
	ps->table_req[request_id].state_NULL = OPENFILTERED;
	return 0;
}

int PortScanner::checkViaFIN(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim){
	memset(buffer, 0, sizeof(buffer));
	int try_remain = 3;
	struct icmp_state icmp_result;
	struct tcp_state tcp_result;
	int data_size = 0;
	int type;

	while(try_remain > 0){
		PortScanner::sendFIN(ip_victim, port_victim, ps, sock_send);
		int match_result = PortScanner::recvMatch(sock_recv, buffer, &data_size, &type, ip_victim, port_victim);
		if(match_result == 1){
			try_remain--;
			continue;
		}
		if(match_result == 0){
			if(type == 1){
				PortScanner::prcICMP(buffer, data_size, &icmp_result);
				int code = icmp_result.code;
				if(icmp_result.type == 3 && (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13)){
					ps->table_req[request_id].state_FIN = FILTERED;
					return 0;
				}
			}
			else if(type == 6){
				PortScanner::prcTCP(buffer, data_size, &tcp_result);
				if(tcp_result.RST == 1){
					ps->table_req[request_id].state_FIN = CLOSED;
					return 0;
				}
			}
		}
	}
	ps->table_req[request_id].state_FIN = OPENFILTERED;
	return 0;
}

int PortScanner::checkViaXmas(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim){
	memset(buffer, 0, sizeof(buffer));
	int try_remain = 3;
	struct icmp_state icmp_result;
	struct tcp_state tcp_result;
	int data_size = 0;
	int type;

	while(try_remain > 0){
		PortScanner::sendXmas(ip_victim, port_victim, ps, sock_send);
		int match_result = PortScanner::recvMatch(sock_recv, buffer, &data_size, &type, ip_victim, port_victim);
		if(match_result == 1){
			try_remain--;
			continue;
		}
		if(match_result == 0){
			if(type == 1){
				PortScanner::prcICMP(buffer, data_size, &icmp_result);
				int code = icmp_result.code;
				if(icmp_result.type == 3 && (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13)){
					ps->table_req[request_id].state_Xmas = FILTERED;
					return 0;
				}
			}
			else if(type == 6){
				PortScanner::prcTCP(buffer, data_size, &tcp_result);
				if(tcp_result.RST == 1){
					ps->table_req[request_id].state_Xmas = CLOSED;
					return 0;
				}
			}
		}
	}
	ps->table_req[request_id].state_Xmas = OPENFILTERED;
	return 0;
}

int PortScanner::checkViaACK(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim){
	memset(buffer, 0, sizeof(buffer));
	int try_remain = 3;
	struct icmp_state icmp_result;
	struct tcp_state tcp_result;
	int data_size = 0;
	int type;

	while(try_remain > 0){
		PortScanner::sendACK(ip_victim, port_victim, ps, sock_send);
		int match_result = PortScanner::recvMatch(sock_recv, buffer, &data_size, &type, ip_victim, port_victim);
		if(match_result == 1){
			try_remain--;
			continue;
		}
		if(match_result == 0){
			if(type == 1){
				PortScanner::prcICMP(buffer, data_size, &icmp_result);
				int code = icmp_result.code;
				if(icmp_result.type == 3 && (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13)){
					ps->table_req[request_id].state_ACK = FILTERED;
					return 0;
				}
			}
			else if(type == 6){
				PortScanner::prcTCP(buffer, data_size, &tcp_result);
				if(tcp_result.RST == 1){
					ps->table_req[request_id].state_ACK = UNFILTERED;
					return 0;
				}
			}
		}
	}
	ps->table_req[request_id].state_ACK = FILTERED;
	return 0;
}

int PortScanner::checkViaUDP(int sock_send, int sock_recv, unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim){
	memset(buffer, 0, sizeof(buffer));
	int try_remain = 3;
	struct icmp_state icmp_result;
	struct tcp_state tcp_result;
	int data_size = 0;
	int type;

	while(try_remain > 0){
		PortScanner::sendUDP(ip_victim, port_victim, ps, sock_send);
		int match_result = PortScanner::recvMatch(sock_recv, buffer, &data_size, &type, ip_victim, port_victim);
		if(match_result == 1){
			try_remain--;
			continue;
		}
		if(match_result == 0){
			if(type == 1){
				PortScanner::prcICMP(buffer, data_size, &icmp_result);
				int code = icmp_result.code;
				if(icmp_result.type == 3 && code == 3){
					ps->table_req[request_id].state_UDP = CLOSED;
					return 0;
				}
				if(icmp_result.type == 3 && (code == 1 || code == 2 || code == 9 || code == 10 || code == 13)){
					ps->table_req[request_id].state_UDP = FILTERED;
					return 0;
				}
			}
			else if(type == 17){
				ps->table_req[request_id].state_UDP = OPEN;
			}
		}
	}
	ps->table_req[request_id].state_UDP = OPENFILTERED;
	return 0;
}

int PortScanner::checkService(unsigned char *buffer, PortScanner *ps, int request_id, char *ip_victim, int port_victim){
	memset(buffer, 0, sizeof(buffer));
	const char *service_query_HTTP = "GET / HTTP\r\n\r\n";
	const char *service_query_SSH = "          ";
	const char *service_query_SMTP = "          ";
	const char *service_query_POP = "          ";
	const char *service_query_WHOIS = "\r\n";
	const char *service_query_IMAP = "          ";
	const char *pattern_HTTP = "HTTP/";
	const char *pattern_SMTP = "220";
	const char *pattern_SSH = "SSH-";
	const char *pattern_POP = "OK";
	const char *pattern_WHOIS = "Whois Server Version ";
	const char *pattern_IMAP = "OK";

	struct timeval tv;

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	PortScanner::getServiceName(port_victim, ps->table_req[request_id].service_type);

	if(port_victim == 80){ //HTTP
		char buffer_send[40];
		memset(buffer_send, 40, 0);
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		int sock_service = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(setsockopt(sock_service, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0){
			printf("setsockopt failed\n");
			return -1;
		}
		if(sock_service < 0){
			printf("checkService(): socket creation failed");
			exit(1);
		}
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port_victim);
		if(inet_aton(ip_victim, &addr.sin_addr) == 0){
			fprintf(stderr, "invalid address\n");
			exit(EXIT_FAILURE);
		}
		memset(&addr.sin_zero, 0, 8);
		if(connect(sock_service, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1){
			//printf("checkService(): connect() failed ");
			close(sock_service);
			return 1;
		}
		strcpy(buffer_send, service_query_HTTP);
		printf("HTTP query sending..\n");
		send(sock_service, buffer_send, 40, 0);
		PortScanner::readSock(sock_service, buffer, 20);
		printf("%s\n", buffer);
		/*check service*/
		char *found = strstr((char *)buffer, pattern_HTTP);
		if(found == NULL){
			ps->table_req[request_id].service_verified = 2;
			strcpy(ps->table_req[request_id].service_version, "unkown");
		}
		else{
			ps->table_req[request_id].service_verified = 1;
			memcpy(ps->table_req[request_id].service_version, found + 5, 3);
			strcpy(ps->table_req[request_id].service_type, "http");
		}
		close(sock_service);
		return 0;
	}
	else if(port_victim == 22){ //SSH
		char buffer_send[40];
		memset(buffer_send, 40, 0);
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		int sock_service = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(setsockopt(sock_service, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0){
			printf("setsockopt failed\n");
			return -1;
		}

		if(sock_service < 0){
			printf("checkService(): socket creation failed");
			exit(1);
		}
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port_victim);
		if(inet_aton(ip_victim, &addr.sin_addr) == 0){
			fprintf(stderr, "invalid address\n");
			exit(EXIT_FAILURE);
		}
		memset(&addr.sin_zero, 0, 8);
		if(connect(sock_service, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1){
			//printf("checkService(): connect() failed ");
			close(sock_service);
			return 1;
		}
		strcpy(buffer_send, service_query_SSH);
		printf("SSH query sending..\n");
		send(sock_service, buffer_send, 40, 0);
		PortScanner::readSock(sock_service, buffer, 20);
		printf("%s\n", buffer);
		/*check service*/
		char *found = strstr((char *)buffer, pattern_SSH);
		if(found == NULL){
			ps->table_req[request_id].service_verified = 2;
			strcpy(ps->table_req[request_id].service_version, "unkown");
		}
		else{
			ps->table_req[request_id].service_verified = 1;
			memcpy(ps->table_req[request_id].service_version, found + 4, 3);
			strcpy(ps->table_req[request_id].service_type, "ssh");
		}
		close(sock_service);
		return 0;
	}
	else if(port_victim == 24){ //SMTP
		char buffer_send[40];
		memset(buffer_send, 40, 0);
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		int sock_service = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(setsockopt(sock_service, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0){
			printf("setsockopt failed\n");
			return -1;
		}
		if(sock_service < 0){
		printf("checkService(): socket creation failed");
		exit(1);
		}
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port_victim);
		if(inet_aton(ip_victim, &addr.sin_addr) == 0){
			fprintf(stderr, "invalid address\n");
			exit(EXIT_FAILURE);
		}
		memset(&addr.sin_zero, 0, 8);
		if(connect(sock_service, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1){
			//printf("checkService(): connect() failed ");
			close(sock_service);
			return 1;
		}
		strcpy(buffer_send, service_query_SMTP);
		printf("SMTP query sending..\n");
		send(sock_service, buffer_send, 40, 0);
		PortScanner::readSock(sock_service, buffer, 20);
		printf("%s\n", buffer);
		/*check service*/
		char *found = strstr((char *)buffer, pattern_SMTP);
		if(found == NULL){
			ps->table_req[request_id].service_verified = 2;
			strcpy(ps->table_req[request_id].service_version, "unkown");
		}
		else{
			ps->table_req[request_id].service_verified = 1;
			strcpy(ps->table_req[request_id].service_type, "smtp");
			strcpy(ps->table_req[request_id].service_version, "unkown");
		}
		close(sock_service);
		return 0;
	}
	else if(port_victim == 110){ //POP
		char buffer_send[40];
		memset(buffer_send, 40, 0);
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		int sock_service = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(setsockopt(sock_service, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0){
			printf("setsockopt failed\n");
			return -1;
		}
		if(sock_service < 0){
		printf("checkService(): socket creation failed");
		exit(1);
		}
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port_victim);
		if(inet_aton(ip_victim, &addr.sin_addr) == 0){
			fprintf(stderr, "invalid address\n");
			exit(EXIT_FAILURE);
		}
		memset(&addr.sin_zero, 0, 8);
		if(connect(sock_service, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1){
			//printf("checkService(): connect() failed ");
			close(sock_service);
			return 1;
		}
		strcpy(buffer_send, service_query_POP);
		printf("POP query sending..\n");
		send(sock_service, buffer_send, 40, 0);
		PortScanner::readSock(sock_service, buffer, 20);
		printf("%s\n", buffer);

		/*check service*/
		char *found = strstr((char *)buffer, pattern_POP);
		if(found == NULL){
			ps->table_req[request_id].service_verified = 2;
			strcpy(ps->table_req[request_id].service_version, "unkown");
		}
		else{
			ps->table_req[request_id].service_verified = 1;
			strcpy(ps->table_req[request_id].service_version, "3");
		}

		close(sock_service);
		return 0;
	}
	else if(port_victim == 43){ //WHOIS
		char buffer_send[40];
		memset(buffer_send, 40, 0);
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		int sock_service = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(setsockopt(sock_service, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0){
			printf("setsockopt failed\n");
			return -1;
		}
		if(sock_service < 0){
		printf("checkService(): socket creation failed");
		exit(1);
		}
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port_victim);
		if(inet_aton(ip_victim, &addr.sin_addr) == 0){
			fprintf(stderr, "invalid address\n");
			exit(EXIT_FAILURE);
		}
		memset(&addr.sin_zero, 0, 8);
		if(connect(sock_service, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1){
			//printf("checkService(): connect() failed ");
			close(sock_service);
			return 1;
		}
		strcpy(buffer_send, service_query_WHOIS);
		printf("WHOIS query sending..\n");
		send(sock_service, buffer_send, 40, 0);
		PortScanner::readSock(sock_service, buffer, 20);
		printf("%s\n", buffer);

		/*check service*/
		char *found = strstr((char *)buffer, pattern_WHOIS);
		if(found == NULL){
			ps->table_req[request_id].service_verified = 2;
			strcpy(ps->table_req[request_id].service_version, "unkown");
		}
		else{
			ps->table_req[request_id].service_verified = 1;
			strcpy(ps->table_req[request_id].service_type, "whois");
			memcpy(ps->table_req[request_id].service_version, found + 21, 3);
		}
		close(sock_service);
		return 0;
	}
	else if(port_victim == 143 || port_victim == 220){ //IMAP
		char buffer_send[40];
		memset(buffer_send, 40, 0);
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		int sock_service = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(setsockopt(sock_service, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0){
			printf("setsockopt failed\n");
			return -1;
		}
		if(sock_service < 0){
		printf("checkService(): socket creation failed");
		exit(1);
		}
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port_victim);
		if(inet_aton(ip_victim, &addr.sin_addr) == 0){
			fprintf(stderr, "invalid address\n");
			exit(EXIT_FAILURE);
		}
		memset(&addr.sin_zero, 0, 8);
		if(connect(sock_service, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1){
			//printf("checkService(): connect() failed ");
			close(sock_service);
			return 1;
		}
		strcpy(buffer_send, service_query_IMAP);
		printf("IMAP query sending..\n");
		send(sock_service, buffer_send, 40, 0);
		PortScanner::readSock(sock_service, buffer, 20);
		printf("%s\n", buffer);

		/*check service*/
		char *found = strstr((char *)buffer, pattern_IMAP);
		if(found == NULL){
			ps->table_req[request_id].service_verified = 2;
			strcpy(ps->table_req[request_id].service_version, "unkown");
		}
		else{
			ps->table_req[request_id].service_verified = 1;
			//strcpy(ps->table_req[request_id].service_type, "imap");
			strcpy(ps->table_req[request_id].service_version, "unkown");
		}

		close(sock_service);
		return 0;
	}
	else{
		strcpy(ps->table_req[request_id].service_version, "n/a");
		ps->table_req[request_id].service_verified = 0;
	}

	return 0;
}


