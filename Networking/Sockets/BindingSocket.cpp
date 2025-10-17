#include <iostream>
#include "BindingSocket.hpp"

//Constructor
HDE::BindingSocket::BindingSocket(int domain, int service, int protocol, int port, unsigned long interface) : SimpleSocket(domain, service, protocol, port, interface) {
    connect_to_network(get_sock(), get_address());
    test_connection(binding);
}

//Definition of connect_to_network
void HDE::BindingSocket::connect_to_network(int sock, struct sockaddr_in address) {
    binding = bind(sock, reinterpret_cast<struct sockaddr*>(&address), sizeof(address));
}

//Getters
int HDE::BindingSocket::get_binding() {
    return binding;
}