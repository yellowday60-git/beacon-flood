LDLIBS=-lpcap

all: beacon-flood

beacon-flood: mac.o main.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f beacon-flood *.o