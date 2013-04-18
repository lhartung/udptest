udpstr: udpstr.c
	gcc -o udpstr udpstr.c -lpthread

clean:
	rm -f udpstr

