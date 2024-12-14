all: rm keys client server

keys:
	openssl genrsa -out server.key 2048
	openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=localhost"

server:
	g++ -o server server.cpp -lssl -lcrypto

client:
	g++ -o client client.cpp -lssl -lcrypto

rm:
	rm -f server client server.key server.crt sslkeys.log

run-server:
	./server server.crt server.key sslkeys.log
