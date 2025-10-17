#include <iostream>
#include <stdio.h>
#include "SimpleSocket.hpp"

#ifndef ConnectingSocket_hpp
#define ConnectingSocket_hpp

namespace HDE {
    class ConnectingSocket : public SimpleSocket {
        public:
            //Constructor
            ConnectingSocket(int domain, int service, int protocol, int port, unsigned long interface);
            //Virtual function from parent
            void connect_to_network(int sock, struct sockaddr_in address);
        private:
            alignas(CACHE_LINE_SIZE) int binding;
    };
}

#endif