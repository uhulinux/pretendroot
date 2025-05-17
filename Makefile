libpretendroot.so: libpretendroot.c
	gcc -fPIC -Wall -shared -ldl -o libpretendroot.so libpretendroot.c

clean:
	rm -f libpretendroot.so

