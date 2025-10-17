#include "Server.hpp"
int main() {
    HDE::Server obj;
}
/* Commands list:

Compiling/Executing:

/usr/bin/clang++ -std=gnu++14 -Wpedantic -ferror-limit=0 -std=c++23 -fcolor-diagnostics -fansi-escape-codes -g /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main && ./a/Networking/Servers/main

Compiling/Executing for maximum performance binary, but longer compile times, bigger binaries, and complex debugging required:

/usr/bin/clang++ -std=gnu++14 -Wpedantic -ferror-limit=0 -std=c++23 -O3 -fcolor-diagnostics -fansi-escape-codes -g /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main && ./a/Networking/Servers/main

Compiling:

/usr/bin/clang++ -std=gnu++14 -Wpedantic -ferror-limit=0 -std=c++23 -fcolor-diagnostics -fansi-escape-codes -g /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main

Compiling for maximum performance binary, but longer compile times, bigger binaries, and complex debugging required:

/usr/bin/clang++ -std=gnu++14 -Wpedantic -ferror-limit=0 -std=c++23 -O3 -fcolor-diagnostics -fansi-escape-codes -g /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main

Executing:

./a/networking/Servers/main

Deleting:

sudo rm -rf a/Networking/Servers/main

- How to use PGO (Final builds only):

Compiling w/ Profile-Guided w/ -03 argument:

/usr/bin/clang++ -std=gnu++14 -Wpedantic -ferror-limit=0 -std=c++23 -O3 -fcolor-diagnostics -fansi-escape-codes -g -fprofile-generate /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main

./a/Networking/Servers/main

ab -n 1000000 -c 100000 http://192.168.12.109:80/

/usr/bin/clang++ -std=gnu++14 -Wpedantic -ferror-limit=0 -std=c++23 -O3 -fcolor-diagnostics -fansi-escape-codes -g -fprofile-use /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main_pgo

./a/Networking/Servers/main_pgo

*/