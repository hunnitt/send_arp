all: send_arp

send_arp: send_arp.o main.o
	g++ -o send_arp main.o send_arp.o -lpcap

send_arp.o: send_arp.cpp send_arp.h
	g++ -c -o send_arp.o send_arp.cpp

main.o: main.cpp send_arp.h send_arp.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -rf send_arp *.o
