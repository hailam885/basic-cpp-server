#ifndef ListeningSocket_hpp
#define ListeningSocket_hpp

#include <iostream>
#include <stdio.h>
#include "BindingSocket.hpp"

namespace HDE {
    class ListeningSocket : public BindingSocket {
        public:
            ListeningSocket(int domain, int service, int protocol, int port, unsigned long interface, int bklg);
            void start_listening();
            int get_listening();
            int get_backlog();
        private:
            int backlog;
            int listening;
    };
}

#endif