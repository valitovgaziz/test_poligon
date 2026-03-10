all: build start

build:
	gcc -o exec.exe main.c fib.c

start:
	.\exec.exe
