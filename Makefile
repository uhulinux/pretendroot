libpretendroot.so: libpretendroot.c
	gcc -fPIC -Wall -shared -ldl -o libpretendroot.so libpretendroot.c

install:
	mkdir -p $(DESTDIR)/usr/bin
	install -m 755 pretendroot $(DESTDIR)/usr/bin/
	mkdir -p $(DESTDIR)/usr/lib
	install -m 755 libpretendroot.so $(DESTDIR)/usr/lib/

clean:
	rm -f libpretendroot.so

