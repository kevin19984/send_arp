all: send_arp

send_arp: main.o getmy.o
	g++ -g -o send_arp main.o getmy.o -lpcap

getmy.o: getmy.cpp getmy.h
	g++ -g -c -o getmy.o getmy.cpp

main.o: main.cpp arpheader.h getmy.h
	g++ -g -c -o main.o main.cpp

clean: 
	rm -f send_arp 
	rm -f *.o
