#ifndef SimpleServer_hpp
#define SimpleServer_hpp

#include "../hdelibc-networking.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fstream>
#include <chrono>
#include <string>
#include <unordered_map>
#include <list>
#include <netdb.h>
#include <thread>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <array>
#include <cerrno>
#include <functional>
#include <atomic>
#include <cstring>
#include <stdio.h>
#include <condition_variable>
#include <ctime>
#include <format>
#include <execution>
#include <pthread.h>
#include <sched.h>
#include <string_view>
#include <span>
//#include <numa.h>
//#include <boost/lockfree/queue.hpp>

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
    Request(int dest, std::string message) : location(dest), msg(std::move(message)) {};
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
    Response(int dest, std::string message) : destination(dest), msg(std::move(message)) {};
    Response(int dest, const char* data, size_t len) : destination(dest), msg(data, len) {};
};

namespace HDE {
    class AddressQueue {
        private:
            std::queue<struct Request> address_queue;
        public:
            void emplace_response(int loc, std::span<const char> data);
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
            void emplace_response(int loc, std::span<const char> data) noexcept;
            void emplace_response(int destination, std::string msg);
            int get_size() const noexcept;
            void closeAllConnections();
            bool empty() const noexcept;
    };
    class SimpleServer {
        public:
            SimpleServer(int domain, int service, int protocol, int port, unsigned long interface, int bklg);
            virtual void launch() = 0;
            ListeningSocket* get_socket();
        private:
            ListeningSocket* socket;
            virtual void accepter(HDE::AddressQueue& address_queue) = 0;
            virtual void handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue) = 0;
            virtual void responder(HDE::ResponderQueue& response) = 0;
    };
}

#endif