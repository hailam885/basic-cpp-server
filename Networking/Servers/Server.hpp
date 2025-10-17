#ifndef Server_hpp
#define Server_hpp

#include "SimpleServer.hpp"

struct Request;

struct Response;

const constexpr int request_cache_size_line = (sizeof(Request) + (sizeof(Request) % CACHE_LINE_SIZE));
const constexpr int response_cache_size_line = (sizeof(Response) + (sizeof(Response) % CACHE_LINE_SIZE));

#define REQUEST_CACHE_SIZE request_cache_size_line
#define RESPONSE_CACHE_SIZE response_cache_size_line

using TimePoint = std::chrono::steady_clock::time_point;
using Clock = std::chrono::steady_clock;

//Mutex objects for multithreading synchronization
extern std::mutex address_queue_mutex;
extern std::mutex responder_queue_mutex;
extern std::mutex r_e_m_mutex;
extern std::mutex console_mutex;
extern std::mutex clean_up_mutex;
extern std::mutex general_mutex;
extern std::mutex file_access_mutex;
extern std::mutex rate_limited_mutex;

namespace HDE {
    //Server configurations
    alignas(CACHE_LINE_SIZE) constexpr int queueCount = 10000000;
    alignas(CACHE_LINE_SIZE) constexpr int Port = 80;
    alignas(CACHE_LINE_SIZE) constexpr int MAX_CONNECTIONS_PER_SECOND = 20;
    //For after a connection is established and waiting for the next step
    alignas(CACHE_LINE_SIZE) constexpr int max_incoming_address_queue_size = 5000000;
    alignas(CACHE_LINE_SIZE) constexpr int max_responses_queue_size = 5000000;

    //Multithreading configurations, multithreading enabled by default
    //It is recommended to have the handler's thread count more than the accepter's and responder's thread count.
    alignas(CACHE_LINE_SIZE) inline int threadsForAccepter = 2;
    alignas(CACHE_LINE_SIZE) inline int threadsForHandler = 3;
    alignas(CACHE_LINE_SIZE) inline int threadsForResponder = 2;
    alignas(CACHE_LINE_SIZE) inline int totalUsedThreads = threadsForAccepter + threadsForHandler + threadsForResponder;

    //configures whether to limit the responder function from checking too much, if yes, by default it waits for 10ms before checking, and automatically disables it when the queue size is too big.
    alignas(CACHE_LINE_SIZE) constexpr bool continuous_responses = true;
    alignas(CACHE_LINE_SIZE) inline int handler_responses_per_second = 200; //responses per second hard limit; cannot go over 1000
    alignas(CACHE_LINE_SIZE) inline int responder_responses_per_second = 200; //responses per second hard limit; can fully disable with continuous_responses. if the value is 100, the responder will sleep for 1000 / val -> 1000 / 100 = 10ms before polling another response from ResponderQueue.

    //This feature ensures thread-safe compatibility between C's printf and C++'s stream operator. When [false], unexpected behavior might occur (only if the program mixes between C/C++ code).
    //true -> server stability; false -> increased performance
    alignas(CACHE_LINE_SIZE) constexpr int IOSynchronization = false;

    //Typically the accepter functions will notify a thread as soon as a request is available. The limit here is to wait before the queue size gets past a certain limit to notify a thread. DO NOT turn this on yet, we do not have enough people to queue up; the server will just not process them.
    //0 -> disabled, 1 -> limit by queue size, 2 -> limit by time
    //right now the wait_before_notify_thread is default to 0, changing it doesn't change anything.
    alignas(CACHE_LINE_SIZE) constexpr int wait_before_notify_thread = 0;
    alignas(CACHE_LINE_SIZE) constexpr int queue_size_limit_before_notify = 20;

    //Define the maximum limit in bytes a client's request can have; recommended to have 30000+.
    alignas(CACHE_LINE_SIZE) constexpr size_t MAX_BUFFER_SIZE = 30721;

    //incoming connections list tracker
    extern std::unordered_map<std::string, std::list<TimePoint>> connection_history;

    //Utility functions
    std::string get_current_time();
    void clean_server_shutdown(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue);
    inline void reportErrorMessage();
    bool is_rate_limited(const std::string& client_ip);

    //OS Internals
    alignas(CACHE_LINE_SIZE) inline const size_t NUM_THREADS = std::thread::hardware_concurrency();
    class Server : public SimpleServer {
        private:
            void accepter(HDE::AddressQueue& address_queue) override;
            void handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue) override;
            void responder(HDE::ResponderQueue& response) override;
            char buffer[MAX_BUFFER_SIZE] = {0};
            int new_socket;
            std::string html_file_path = "/Users/trangtran/Desktop/coding_files/a/Networking/Servers/html_templates/random.html";
            std::string main_page_template_cache;
            void load_cache();
        public:
            Server();
            void launch() override;
            inline void logClientInfo(const std::string_view processing_component, const std::string_view message) const;
    };
}

#endif