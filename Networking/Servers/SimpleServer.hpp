#ifndef SimpleServer_hpp
#define SimpleServer_hpp

#include "../hdelibc-networking.hpp"
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <cstring>
#include <execution>
#include <format>
#include <fstream>
#include <functional>
#include <format>
#include <netinet/in.h>
#include <string>
#include <unordered_map>
#include <list>
#include <netdb.h>
#include <thread>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <iostream>
#include <thread>
#include <stdio.h>
#include <pthread.h>
#include <sched.h>
#include <string_view>
#include <span>
#include <utility>
#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/LogMacros.h>
#include <quill/Logger.h>
#include "quill/sinks/ConsoleSink.h"
#include "quill/std/WideString.h"
#include <sys/time.h>
#include <unistd.h>
//#include <numa.h>
//#include <boost/lockfree/queue.hpp>

#ifdef __APPLE__
    #include <sys/event.h>
#elif __linux__
    #include <sys/epoll.h>
#endif

//to use alignas() specifier
constexpr int returnNextBiggestPowerOfTwo(const int& num) {
    int res = 1;
    while (res < num) {
        res *= 2;
    }
    return res;
}

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
};

struct Response {
    alignas(CACHE_LINE_SIZE) int destination = -1;
    std::string msg = "";
    inline bool operator==(const struct Response& other) {
        if (destination == other.destination && msg == other.msg) return true;
        else return false;
    }
    inline bool operator!=(const struct Response& other) {
        if (destination == other.destination && msg == other.msg) return false;
        else return true;
    }
    Response() = default;
    Response(int dest, std::string_view message) : destination(dest), msg(message) {};
    Response(int dest, const char* data, size_t len) : destination(dest), msg(data, len) {};
};

namespace HDE {
    class AddressQueue {
        private:
            std::queue<struct Request> address_queue;
        public:
            void emplace_response(int loc, std::span<const char> data, quill::Logger* logger);
            void emplace_response(const int location, const std::string_view msg, quill::Logger* logger);
            struct Request get_response();
            int get_size() const noexcept;
            void closeAllConnections();
            bool empty() const noexcept;
    };
    class ResponderQueue {
        private:
            std::queue<struct Response> allResponses;
        public:
            struct Response get_response() noexcept;
            void emplace_response(const int destination, const std::string_view msg, quill::Logger* logger);
            //void emplace_response(const int destination, const std::span<const char> data, quill::Logger* logger);
            int get_size() const noexcept;
            void closeAllConnections();
            bool empty() const noexcept;
    };
    class SimpleServer {
        public:
            SimpleServer(int domain, int service, int protocol, int port, unsigned long interface, int bklg);
            virtual void launch(quill::Logger* logger) = 0;
            ListeningSocket* get_socket();
        private:
            ListeningSocket* socket;
            virtual void accepter(HDE::AddressQueue& address_queue, quill::Logger* logger) = 0;
            virtual void handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue, quill::Logger* logger) = 0;
            virtual void responder(HDE::ResponderQueue& response, quill::Logger* logger) = 0;
    };
}

#endif
