CC = gcc
CFLAGS = -W -Wall
LIBS = -lssl

pwret: main.c
	$(CC) $(CFLAGS)  $^ -o $@ $(LIBS)

clean:
	rm *.o
	rm pwret