#include <iostream>
#include <stdio.h>
#include "SimpleSocket.hpp"

#ifndef BindingSocket_hpp
#define BindingSocket_hpp

namespace HDE {
    class BindingSocket : public SimpleSocket {
        public:
            //Constructor
            BindingSocket(int domain, int service, int protocol, int port, unsigned long interface);
            int get_binding();
        private:
            void connect_to_network(int sock, struct sockaddr_in address);
            alignas(CACHE_LINE_SIZE) int binding;
    };
}

#endif