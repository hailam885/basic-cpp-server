#include "Server.hpp"

int main() {
    quill::Backend::start();
    auto console_sink = quill::Frontend::create_or_get_sink<quill::ConsoleSink>("sink_id_1");
    quill::Logger* logger = quill::Frontend::create_or_get_logger("root", std::move(console_sink));
    logger->set_log_level(quill::LogLevel::TraceL3);
    HDE::Server obj = HDE::Server(logger);
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

ab -n 10000000 -c 100000 http://192.168.12.109:80/

/usr/bin/clang++ -std=gnu++14 -Wpedantic -ferror-limit=0 -std=c++23 -O3 -fcolor-diagnostics -fansi-escape-codes -g -fprofile-use /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main_pgo

./a/Networking/Servers/main_pgo

*/