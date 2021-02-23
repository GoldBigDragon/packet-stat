all: packet-stat

packet-stat: main.o
	g++ -o packet-stat main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp 

clean:
	rm -f packet-stat *.o
