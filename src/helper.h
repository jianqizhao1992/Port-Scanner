#ifndef HELPER_H_
#define HELPER_H_

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include "portScanner.h"

class Helper {
public:
	static void parse_args(PortScanner &, int, char **);
	static void parse_ports(PortScanner &, char *);
	static void parse_ip_prefix(PortScanner &, char *);
	static void parse_ip_file(PortScanner &, char *);
};

#endif /* HELPER_H_ */
