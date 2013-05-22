all: tracer target

tracer: tracer.cpp
	g++ -O3 -o $@ $<

target: target.c
	gcc -O3 -o $@ $<
