CC := g++

FILES := $(shell find ./src -name '*.cc')

build:
	$(CC) $(FILES) -o main.out
