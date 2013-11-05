udptest: udptest.c rxbuff.c
	gcc -o udptest udptest.c rxbuff.c -lpthread

clean:
	rm -f udptest

