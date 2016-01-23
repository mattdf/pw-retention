CC = gcc
CFLAGS = -W -Wall
LIBS = -lssl -lsqlite3

pwret: main.c fs.c
	$(CC) $(CFLAGS)  $^ -o $@ $(LIBS)

clean:
	rm *.o
	rm pwret