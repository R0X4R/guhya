CC = gcc
CFLAGS = -Wall -O2 -Iinclude 
LIBS = -lcurl -lpcre2-8 -lpthread

TARGET = guhya

SRCS = src/main.c src/scanner.c src/network.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

src/%.o: src/%.c include/guhya.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)