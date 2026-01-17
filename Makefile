CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11
LIBS = -lpcap -lpthread
TARGET = cshark

all: $(TARGET)

$(TARGET): cshark_p1.c
	$(CC) $(CFLAGS) -o $(TARGET) cshark_p1.c cshark_p2.c cshark_p3.c cshark_p4.c helper.c $(LIBS)

clean:
	rm -f $(TARGET) *.o
