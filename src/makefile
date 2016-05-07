all:
	g++ -pthread -D_REENTRANT -std=c++0x helper.cpp functions.cpp portScanner.cpp run.cpp -o run
test:
	gcc -D_BSD_SOURCE run_test2.c -o run_test2
	g++ run_test.cpp -o run_test
clean:
	rm -f *o run
