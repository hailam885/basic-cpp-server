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
            alignas(CACHE_LINE_SIZE) int backlog = 8192;
            alignas(CACHE_LINE_SIZE) int listening;
    };
}

#endif