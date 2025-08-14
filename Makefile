CC = gcc
FLAGS = -O0 -g -Wall -Wextra
SRC = alloc.c
OUT = alloc

.PHONY: all clean

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(FLAGS) -o $(OUT) $(SRC)

clean:
	rm -rf $(OUT)
