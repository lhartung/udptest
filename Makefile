udptest: udptest.c
	gcc -o udptest udptest.c -lpthread

clean:
	rm -f udptest

