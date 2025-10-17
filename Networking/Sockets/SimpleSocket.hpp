#ifndef SimpleSocket_hpp
#define SimpleSocket_hpp

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>

//use AF_INET6 for IPv6, AF_INET for IPv4

namespace HDE {
    class SimpleSocket {
        public:
            //use SOCK_STREAM later
            //Constructor
            SimpleSocket(int domain, int service, int protocol, int port, unsigned long interface);
            //Virtual function to connect to the network
            virtual void connect_to_network(int sock, struct sockaddr_in address) = 0;
            //Function to test connections
            void test_connection(int item_to_test);
            //Getter functions
            struct sockaddr_in get_address();
            int get_sock();
        private:
            struct sockaddr_in address;
            int sock;
    };
}

#endif //Simple Socket hpp