CC = g++
CFLAGS = -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -fsanitize=address,undefined -g
LINKS = -lcrypto -lssl
MKDIR = mkdir -p

all: podpis

podpis:
	${MKDIR} ./bin/
	${CC} ${CFLAGS} ./podpis.cpp -o ./bin/podpis ${LINKS}
	
clean:
	rm -rf bin