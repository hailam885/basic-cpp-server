#include "SimpleServer.hpp"

HDE::SimpleServer::SimpleServer(int domain, int service, int protocol, int port, unsigned long interface, int bklg) {
    socket = new ListeningSocket(domain, service, protocol, port, interface, bklg);
}

HDE::ListeningSocket* HDE::SimpleServer::get_socket() {
    return socket;
}

constexpr int returnNextBiggestPowerOfTwo(const int& num) {
    int res = 1;
    while (res <= num) {
        res *= 2;
    }
    return res;
}