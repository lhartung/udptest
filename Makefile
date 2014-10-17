udptest: udptest.c rxbuff.c
	gcc -o udptest udptest.c rxbuff.c -lm -lpthread

clean:
	rm -f udptest

