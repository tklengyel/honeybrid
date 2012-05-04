#Dionaea XMPP-listener
#Modified from Gloox example code to log all valid XML message to a local FIFO queue
#Requires Gloox 1.0 (or later) and LibXML++ 2.6
#
#Tamas K Lengyel 2012

#Change this to the location where you installed Gloox to
GLOOXINC=/opt/gloox/include
GLOOXLIB=/opt/gloox/lib

CC=g++
LDFLAGS=-L$(GLOOXLIB)
CFLAGS=-c -Wall -g -I$(GLOOXINC) `pkg-config --cflags libxml++-2.6`
SOURCES=xmpp_listener.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=xmpp_listener
LIBS=-lgloox -lxml++-2.6

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm xmpp_listener.o xmpp_listener
