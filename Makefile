udptest: udptest.c rxbuff.c tsutil.c
	gcc -o udptest udptest.c rxbuff.c tsutil.c -lm -lpthread

clean:
	rm -f udptest

