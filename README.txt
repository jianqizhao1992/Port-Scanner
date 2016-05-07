Project4: Port Scanner

Yuxuan Chai    yuchai
Jianqi Zhao    zhao61
-----------------------------------
Description:
This project is to implement a multi-threaded port scanner with the functions similar to nmap. It contains the following files:
1.function.cpp: Contains the functions' wrappers, including the functions for "checkViaSYN(IP, port)", "checkService(IP, port)", etc..  
2.helper.cpp: A helper file used for parsing user's input
3.helper.h: header file for helper.cpp
4.portScanner.cpp: contains the small functions for this project, they contribute for function wrappers in functions.cpp
5.portScanner.h: header file for portScanner.cpp
6.run.cpp: main() function here, mostly responsible for multi-thread function
7.makefile: use to compile the program

Usage:
In Linux(blondie)'s terminal, go the root folder, "make" the files; then use "./run" to run the program, after that you can follow the instructions on screen

