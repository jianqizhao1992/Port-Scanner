#include "helper.h"
#include "portScanner.h"

void printRequestTable(struct request_tuple *table_req, int num){
	int i = 0;
	for(i = 0; i < num; i++){
		printf("\n");
		printf("ip: ");
		printf("%s\n", table_req[i].request_ip);
		printf("port: ");
		printf("%d\n", table_req[i].request_port);
		printf("thread id: ");
		printf("%d\n", table_req[i].th_process);
		printf("state_ACK: ");
		printf("0x%x\n", table_req[i].state_ACK);
		printf("state_FIN: ");
		printf("0x%x\n", table_req[i].state_FIN);
		printf("state_NULL: ");
		printf("0x%x\n", table_req[i].state_NULL);
		printf("state_SYN: ");
		printf("0x%x\n", table_req[i].state_SYN);
		printf("state_UDP: ");
		printf("0x%x\n", table_req[i].state_UDP);
		printf("state_Xmas: ");
		printf("0x%x\n", table_req[i].state_Xmas);
		printf("state_conclude: ");
		printf("0x%x\n", table_req[i].state_concluion);
		printf("service_type: %s\n", table_req[i].service_type);
		printf("service version: %s\n", table_req[i].service_version);
		printf("service verified: %d\n", table_req[i].service_verified);
	}
}
std::string getStateName(char state_num){
	switch((int)state_num){
		case 0:
			return "Undetected";
			break;
		case 0x01:
			return "Open";
			break;
		case 0x02:
			return "Closed";
			break;
		case 0x03:
			return "Filtered";
			break;
		case 0x04:
			return "Unfiltered";
			break;
		case 0x05:
			return "Open|Filtered";
			break;
	}
	return "Null";
}
//    IP      Port    Service Name (if applicable)       Results
void printResult(struct request_tuple *table_req, int num_req){
	printf("------------------------------ Result ---------------------------------\n");
	printf("%8s%12s%10s%55s%59s\n", "IP", "Port", "Service", "Results", "Conclusion");
	int i;
	std::string result_syn;
	std::string result_null;
	std::string result_xmass;
	std::string result_fin;
	std::string result_ack;
	std::string result_udp;
	std::string result_conclude;

	for(i = 0; i < num_req; i++){
		result_syn = "SYN(" + getStateName(table_req[i].state_SYN) + ")";
		result_null = "NULL(" + getStateName(table_req[i].state_NULL) + ")";
		result_xmass = "Xmass(" + getStateName(table_req[i].state_Xmas) + ")";
		result_fin = "FIN(" + getStateName(table_req[i].state_FIN) + ")";
		result_ack = "ACK(" + getStateName(table_req[i].state_ACK) + ")";
		result_udp = "UDP(" + getStateName(table_req[i].state_UDP) + ")";
		result_conclude = getStateName(table_req[i].state_concluion);
		printf("%10s%6d%10s%28s%31s%28s%25s\n%61s%26s%28s\n", table_req[i].request_ip, table_req[i].request_port, table_req[i].service_type, result_syn.c_str(), result_null.c_str(), result_xmass.c_str(), result_conclude.c_str(), result_ack.c_str(), result_udp.c_str(), result_fin.c_str());
	}
}

void *threadBegin(void *a){
	int next;
	char ip_victim[INET_ADDRSTRLEN];
	int port_victim;
	struct multith_feed *feed = (struct multith_feed *)a;
	unsigned char buffer[65536];
	int sock_send = socket(PF_INET , SOCK_RAW, IPPROTO_TCP);
	int sock_recv = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	printf("thread %d create send socket %d\n", feed->th_id, sock_send);
	printf("thread %d create recv socket %d\n", feed->th_id, sock_recv);
	fcntl(sock_recv, F_SETFL, O_NONBLOCK);
	/* do a IP_HDRINCL call, to make sure that the kernel knows the header is included in the data, and doesn't insert its own header */
	{
		int one = 1;
		const int *val = &one;
		if(setsockopt (sock_send, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
		    printf ("Warning: Cannot set HDRINCL!\n");
		}
	}

	while(feed->ps_addr->num_next_req < feed->ps_addr->num_req){
		pthread_mutex_lock(&(feed->ps_addr->mutex1));
		next = feed->ps_addr->num_next_req++;
		if(next >= feed->ps_addr->num_req){
			close(sock_send);
			close(sock_recv);
			return NULL;
		}
		strcpy(ip_victim, feed->ps_addr->table_req[next].request_ip);
		port_victim = feed->ps_addr->table_req[next].request_port;
		printf("thread %d take num_next, left: %d\n", feed->th_id, feed->ps_addr->num_next_req);
		pthread_mutex_unlock(&(feed->ps_addr->mutex1));

		std::set<std::string>::iterator it_syn, it_null, it_fin, it_xmas, it_ack, it_udp;
		it_syn = feed->ps_addr->request_scan_flag.find("SYN");
		it_null = feed->ps_addr->request_scan_flag.find("NULL");
		it_fin = feed->ps_addr->request_scan_flag.find("FIN");
		it_xmas = feed->ps_addr->request_scan_flag.find("Xmas");
		it_ack = feed->ps_addr->request_scan_flag.find("ACK");
		it_udp = feed->ps_addr->request_scan_flag.find("UDP");

		if(it_syn != feed->ps_addr->request_scan_flag.end() || feed->ps_addr->check_all == 1){
			PortScanner::checkViaSYN(sock_send, sock_recv, buffer, feed->ps_addr, next, ip_victim, port_victim);
		}
		if(it_null != feed->ps_addr->request_scan_flag.end() || feed->ps_addr->check_all == 1){
			PortScanner::checkViaNULL(sock_send, sock_recv, buffer, feed->ps_addr, next, ip_victim, port_victim);
		}
		if(it_fin != feed->ps_addr->request_scan_flag.end() || feed->ps_addr->check_all == 1){
			PortScanner::checkViaFIN(sock_send, sock_recv, buffer, feed->ps_addr, next, ip_victim, port_victim);
		}
		if(it_xmas != feed->ps_addr->request_scan_flag.end() || feed->ps_addr->check_all == 1){
			PortScanner::checkViaXmas(sock_send, sock_recv, buffer, feed->ps_addr, next, ip_victim, port_victim);
		}
		if(it_ack != feed->ps_addr->request_scan_flag.end() || feed->ps_addr->check_all == 1){
			PortScanner::checkViaACK(sock_send, sock_recv, buffer, feed->ps_addr, next, ip_victim, port_victim);
		}
		if(it_udp != feed->ps_addr->request_scan_flag.end() || feed->ps_addr->check_all == 1){
			PortScanner::checkViaUDP(sock_send, sock_recv, buffer, feed->ps_addr, next, ip_victim, port_victim);
		}
		//a method to get the state conclusion, only open/filtered port need to be detect service
		PortScanner::stateConclude(feed->ps_addr, next);

		if(PortScanner::checkService(buffer, feed->ps_addr, next, ip_victim, port_victim) == 1){
			printf("connect() to ip: %s, port: %d failed!\n", ip_victim, port_victim);
			feed->ps_addr->table_req[next].service_verified = 0;
			strcpy(feed->ps_addr->table_req[next].service_version, "unkown");
		}

		feed->ps_addr->table_req[next].th_process = feed->th_id;
		feed->ps_addr->num_done_req++;
		printf("thread %d add num_done\n", feed->th_id);

	}
	close(sock_send);
	close(sock_recv);
	return NULL;
}

int main(int argc, char *argv[]) {

	PortScanner scanner_x;
	Helper::parse_args(scanner_x, argc, argv);
	/*
	std::cout << "--- result ---" << std::endl << std::endl;
	std::cout << "specified ip address: " << std::endl;
	for(std::set<std::string>::iterator it = scanner_x.request_ip.begin(); it != scanner_x.request_ip.end(); ++it){
		std::cout << *it << std::endl;
	}
	std::cout << std::endl;
	std::cout << "specified ports: " << std::endl;
	for(std::set<int>::iterator iti = scanner_x.request_ports.begin(); iti != scanner_x.request_ports.end(); ++iti){
		std::cout << *iti << std::endl;
	}
	std::cout << std::endl;
	std::cout << "specified scan flag: " << std::endl;
	for(std::set<std::string>::iterator it = scanner_x.request_scan_flag.begin(); it != scanner_x.request_scan_flag.end(); ++it){
		std::cout << *it << std::endl;
	}
	std::cout << std::endl;
	std::cout << "speed-up (threads): " << std::endl;
	std::cout << scanner_x.speed_up << std::endl << std::endl;
	*/

	scanner_x.getLocalIP();
	clock_t start = clock();
	clock_t finish;

	scanner_x.num_req = scanner_x.request_ip.size() * scanner_x.request_ports.size();
	printf("num_req: %d\n", scanner_x.num_req);
	scanner_x.initRequestTable();
	scanner_x.forgeRequestTable();
	//printf("num_req: %d\n", scanner_x.num_req);
	//printf("--------------inititial request table--------------\n");
	//printRequestTable(scanner_x.table_req, scanner_x.num_req);
	//printf("---------------begin task-----------------------\n");
	printf("Scanning...\n\n");

	{
		int i;
		int num_thread = scanner_x.speed_up;
		pthread_t thread[num_thread];
		struct multith_feed feed[num_thread];
		int iret[num_thread];
		for(i = 0; i < num_thread; i++){
			feed[i].ps_addr = &scanner_x;
			feed[i].th_id = i;
			if((iret[i] = pthread_create(&thread[i], NULL, &threadBegin, &feed[i])) != 0){
				printf("Thread creation failed: %d\n", iret[i]);
				exit(EXIT_FAILURE);
			}
		}
		for(i = 0; i < num_thread; i++){
			if(pthread_join(thread[i], NULL) == 0){
				printf("%d join successfully\n", i);
			}
		}
		finish = clock();
		double task_time = (double)(finish - start)/(double)CLOCKS_PER_SEC;
		printf("\nScan took %f seconds\n", task_time);

		//printf("---------------result--------------");
		printResult(scanner_x.table_req, scanner_x.num_req);
		//printRequestTable(scanner_x.table_req, scanner_x.num_req);
		exit(EXIT_SUCCESS);
	}

	/*test
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	scanner_syn.sendXmas("129.79.247.87", 79, s);
	close(s);
	*/
}
