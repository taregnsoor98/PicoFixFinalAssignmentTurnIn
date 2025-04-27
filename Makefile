all: PICOFoxweb

clean:
	@rm -rf *.o
	@rm -rf PICOFoxweb

PICOFoxweb: main.o httpd.o
	gcc -o PICOFoxweb $^ -lsqlite3 -lcrypto

main.o: main.c httpd.h
	gcc -c -o main.o main.c

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c -Wno-deprecated-declarations

install: PICOFoxweb
	sudo install -m 755 PICOFoxweb /usr/local/bin/PICOFoxweb
	sudo install -m 644 pico-foxweb.service /etc/systemd/system/pico-foxweb.service
	sudo systemctl daemon-reload
	sudo systemctl enable pico-foxweb.service
	sudo systemctl start pico-foxweb.service
	echo "PICOFoxweb installed and started."

uninstall:
	sudo systemctl stop pico-foxweb.service
	sudo systemctl disable pico-foxweb.service
	sudo rm -f /usr/local/bin/PICOFoxweb
	sudo rm -f /etc/systemd/system/pico-foxweb.service
	sudo systemctl daemon-reload
	echo "PICOFoxweb uninstalled."
