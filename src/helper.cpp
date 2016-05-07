#include "helper.h"

void Helper::parse_ports(PortScanner &scanner_x, char *argv){
	int i;
	char *pch;
	char *pch_sub;
	int lower = -1;
	int higher = -1;
	pch = strtok(argv, " ,");
	while(pch != NULL){
		//std::cout << pch << std::endl;
		{
			if(std::strpbrk(pch, "-") == NULL){
				scanner_x.request_ports.insert(atoi(pch));
			}
			else{
				pch_sub = strtok(pch, "-");
				while(pch_sub != NULL){
					if(lower == -1 || higher == -1){
						lower = atoi(pch_sub);
						higher = atoi(pch_sub);
					}
					else{
						if(atoi(pch_sub) < lower)
							lower = atoi(pch_sub);
						else
							higher = atoi(pch_sub);
					}
					pch_sub = strtok(NULL, "-");
				}
				for(i = lower; i <= higher; i++){
					scanner_x.request_ports.insert(i);
				}
			}
		}
		pch = strtok(NULL, " ,");
	}
}

void Helper::parse_ip_prefix(PortScanner &scanner_x, char *argv){
	int ip_section[4];
	int upper[4]; //indicate upper bound for ip address section
	int lower[4];
	int mask;
	int i, j;
	char *pch;
	char *pch_sub;
	char *ip;
	pch = strtok(argv, "/");
	while(pch != NULL){
		if(std::strpbrk(pch, ".") != NULL){
			ip = pch;
		}
		else{
			mask = atoi(pch);
		}
		pch = strtok(NULL, "/");
	}
	i = 0;
	pch_sub = strtok(ip, ".");
	while(pch_sub != NULL){
		ip_section[i] = atoi(pch_sub);
		i++;
		pch_sub = strtok(NULL, ".");
	}
	//std::cout << "ip_read: " << ip_section[0] << "." << ip_section[1] << "." << ip_section[2] << "." << ip_section[3] << std::endl;
	//std::cout << "mask: " << mask << std::endl;
	if(mask > 32 || mask < 0){
		std::cout << "   error: invalid ip prefix" << std::endl;
		exit(0);
	}
	for(i = 0; i < 4; i++){
		int temp = (i+1)*8 - mask;
		int toggle_range;
		if(temp < 0){
			toggle_range = 0;
		}
		else if(temp > 8){
			toggle_range = 8;
		}
		else
			toggle_range = temp;
		lower[i] = ip_section[i];
		upper[i] = ip_section[i];
		for(j = 0; j < toggle_range; j++){
			upper[i] |= 1 << j;
			lower[i] &= ~(1 << j);
		}
	}
	int a1, a2, a3, a4;
	//print out
	for(a1 = lower[0]; a1 <= upper[0]; a1++){
		for(a2 = lower[1]; a2 <= upper[1]; a2++){
			for(a3 = lower[2]; a3 <= upper[2]; a3++){
				for(a4 = lower[3]; a4 <= upper[3]; a4++){
					char ip_address[25];
					sprintf(ip_address, "%d.%d.%d.%d", a1, a2, a3, a4);
					scanner_x.request_ip.insert(ip_address);
					//std::cout << ip_address << std::endl;
				}
			}
		}
	}

}

void Helper::parse_ip_file(PortScanner &scanner_x, char *filename){
	std::ifstream input(filename);
	for(std::string line; getline(input, line); ){
		scanner_x.request_ip.insert(line);
	}
	input.close();
}

void Helper::parse_args(PortScanner &scanner_x, int argc, char *argv[]){
	int i;
	std::cout << std::endl;
	if(argc < 2){
		std::cout << "   Too few arguments! Use '--help' for details" << std::endl;
		exit(0);
	}
	else if(argc == 2){
		if(strcmp(argv[1], "--help") == 0){
			std::cout << "   Help information:" << std::endl;
			std::cout << "--ports <ports to scan> ie. 1,2,3-7" << std::endl;
			std::cout << "--ip <ip to scan> ie. 127.0.0.1 " << std::endl;
			std::cout << "--prefix <IP prefix to scan> ie. 127.0.0.1/24" << std::endl;
			std::cout << "--file <file name containing IP addresses> ie. ./portScanner --file filename.txt" << std::endl;
			std::cout << "--speedup <parallel threads to use> ie. ./portScanner --speedup 10" << std::endl;
			std::cout << "--scan <one or more scans> ie. ./portScanner --scan SYN NULL XMAS" << std::endl;
			std::cout << std::endl;
			exit(0);
		}
		else{
			std::cout << "   Too few arguments! Use '--help' for details" << std::endl;
			std::cout << std::endl;
			exit(0);
		}
	}
	else{
		for(i = 1; i < argc; i++){
			if(strcmp(argv[i], "--ports") == 0){
				Helper::parse_ports(scanner_x, argv[i+1]);
				i++;
			}
			else if(strcmp(argv[i], "--ip") == 0){
				scanner_x.request_ip.insert(argv[i+1]);
				i++;
			}
			else if(strcmp(argv[i], "--prefix") == 0){
				Helper::parse_ip_prefix(scanner_x, argv[i+1]);
				i++;
			}
			else if(strcmp(argv[i], "--file") == 0){
				Helper::parse_ip_file(scanner_x, argv[i+1]);
				i++;
			}
			else if(strcmp(argv[i], "--speedup") == 0){
				scanner_x.speed_up = atoi(argv[i+1]);
				i++;
			}
			else if(strcmp(argv[i], "--scan") == 0){
				while((i+1 < argc) && (!strcmp(argv[i+1], "SYN") || !strcmp(argv[i+1], "NULL") || !strcmp(argv[i+1], "FIN") || !strcmp(argv[i+1], "XMAS") || !strcmp(argv[i+1], "ACK") || !strcmp(argv[i+1], "UDP"))){
					scanner_x.request_scan_flag.insert(argv[i+1]);
					i++;
				}
			}
			else{
				//std::cout << i << std::endl;
				std::cout << "error: invalid arguments" << std::endl;
				exit(0);
			}
		}
		std::cout << std::endl;
	}
}
