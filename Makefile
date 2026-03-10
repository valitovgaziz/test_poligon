all: build start

build:
	gcc -o exec.exe main.c

start:
	.\exec.exe