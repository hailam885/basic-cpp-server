#ifndef SimpleServer_hpp
#define SimpleServer_hpp

#include "../hdelibc-networking.hpp"
#include <algorithm>
#include <arm_acle.h>
#include <arm_neon.h>
#include <arpa/inet.h>
#include <arpa/ftp.h>
#include <arpa/nameser.h>
#include <arpa/telnet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <errno.h>
#include <execution>
#include <filesystem>
#include <fcntl.h>
#include <format>
#include <fstream>
#include <functional>
#include <format>
#include <iomanip>
#include <iostream>
#include <list>
#include <malloc/malloc.h>
#include <malloc/_malloc.h>
//#include <malloc.hpp>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/bootp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <new>
#include <thread>
#include <pthread.h>
#include <queue>
#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/LogMacros.h>
#include <quill/Logger.h>
#include "quill/sinks/ConsoleSink.h"
#include "quill/std/WideString.h"
#include "quill/std/Chrono.h"
#include <regex>
#include <sched.h>
#include <shared_mutex>
//#include <simd/simd.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <span>
#include <sstream>
#include <stdio.h>
#include <string>
#include <string.h>
#include <string_view>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
//#include <numa.h>
//#include <boost/lockfree/queue.hpp>

//for cpu core pinning
#ifdef __linux
    #include <sched.h>
    #include <fstream>
    #include <sstream>
#elif __APPLE__
    //Don't uncomment
    //#include <mach/thread_policy.h>
    //#include <mach/thread_act.h>
    #include <mach/mach.h>
    #include <sys/sysctl.h>
#endif

/*
#ifdef __APPLE__
    #include <sys/event.h>
#elif __linux__
    #include <sys/epoll.h>
#endif*/

//to use alignas() specifier
constexpr int returnNextBiggestPowerOfTwo(const int& num);

//might need to optimize to string_view instead of string
struct Request {
    alignas(CACHE_LINE_SIZE) int location = -1;
    std::string msg = "";
    inline bool operator==(const struct Request& other) {
        if (location == other.location && msg == other.msg) return true;
        else return false;
    }
    inline bool operator!=(const struct Request& other) {
        if (location == other.location && msg == other.msg) return false;
        else return true;
    }
    Request() = default;
    Request(int dest, std::string_view message) : location(dest), msg(message) {};
    Request(int loc, const char* data, size_t len) : location(loc), msg(data, len) {};
    ~Request() = default;
};

struct Response {
    alignas(CACHE_LINE_SIZE) int destination = -1;
    std::string msg = "";
    inline bool operator==(const struct Response& other) {
        if (destination == other.destination && msg == other.msg) return true;
        else return false;
    }
    inline bool operator!=(const struct Response& other) {
        if (destination == other.destination && msg == other.msg) return true;
        else return false;
    }
    Response() = default;
    Response(int dest, std::string_view message) : destination(dest), msg(message) {};
    Response(int dest, const char* data, size_t len) : destination(dest), msg(data, len) {};
    ~Response() = default;
};

namespace HDE {
    class SimpleServer {
        public:
            SimpleServer(int domain, int service, int protocol, int port, unsigned long interface, int bklg);
            virtual void launch(quill::Logger* logger) = 0;
            ListeningSocket* get_socket();
        private:
            ListeningSocket* socket;
            //void accepter(HDE::AddressQueue& address_queue, quill::Logger* logger);
            //void handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue, quill::Logger* logger);
            //void responder(HDE::ResponderQueue& response, quill::Logger* logger);
    };
}

#endif
