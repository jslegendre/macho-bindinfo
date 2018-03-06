all: test output clean

test:
	python binddump_test.py

output: 
	gcc -O2 -Wall binddump.c -o binddump

clean:
	@rm binddump_.c
	@rm binddump_.o
	@rm binddump_.so
