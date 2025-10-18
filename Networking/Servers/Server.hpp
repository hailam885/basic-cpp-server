#ifndef Server_hpp
#define Server_hpp

#include "SimpleServer.hpp"

struct Request;
struct Response;
struct RateLimiter {
    static constexpr size_t MAX_SIZE = 100;  // Max requests to track
    std::array<std::chrono::steady_clock::time_point, MAX_SIZE> times;
    size_t head = 0;
    size_t count = 0;
    
    void add(std::chrono::steady_clock::time_point tp) {
        times[head] = tp;
        head = (head + 1) % MAX_SIZE;
        if (count < MAX_SIZE) ++count;
    }
    
    size_t count_recent(std::chrono::seconds window) const {
        auto now = std::chrono::steady_clock::now();
        size_t recent = 0;
        for (size_t i = 0; i < count; ++i) {
            if (now - times[i] <= window) {
                ++recent;
            }
        }
        return recent;
    }
};
//For Sharded Lock
constexpr size_t NUM_RATE_LIMIT_SHARDS = 16;

struct RateLimitShard {
    alignas(CACHE_LINE_SIZE) std::mutex mutex;
    std::unordered_map<std::string, RateLimiter> limiters;
    char padding[CACHE_LINE_SIZE - sizeof(std::mutex) - sizeof(std::unordered_map<std::string, RateLimiter>)];
};

inline RateLimitShard rate_limit_shards[NUM_RATE_LIMIT_SHARDS];

//Mutex objects for multithreading synchronization
alignas(CACHE_LINE_SIZE) extern std::mutex address_queue_mutex;
alignas(CACHE_LINE_SIZE) extern std::mutex responder_queue_mutex;
alignas(CACHE_LINE_SIZE) extern std::mutex r_e_m_mutex;
alignas(CACHE_LINE_SIZE) extern std::mutex init_mutex;
alignas(CACHE_LINE_SIZE) extern std::mutex clean_up_mutex;
alignas(CACHE_LINE_SIZE) extern std::mutex general_mutex;
alignas(CACHE_LINE_SIZE) extern std::mutex file_access_mutex;
alignas(CACHE_LINE_SIZE) extern std::mutex rate_limited_mutex;

struct alignas(CACHE_LINE_SIZE) serverStatus {
    std::atomic<bool> finished_initialization;
    std::atomic<bool> stop_server = false;
    char padding[CACHE_LINE_SIZE - 2 * sizeof(std::atomic<bool>)];
};

inline serverStatus serverState;

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
    //For now changing the thread count is not available.
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
    extern std::unordered_map<std::string, RateLimiter> connection_history;

    //logging configurations
    //0 -> minimal logs, 1 -> reduced logs, 2 -> default logs, 3 -> full (normal + debugging) logs
    constexpr inline int log_level = 2;

    //Utility functions
    inline std::string_view get_current_time();
    void clean_server_shutdown(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue);
    inline void reportErrorMessage(quill::Logger* logger);
    bool is_rate_limited(const std::string_view client_ip);

    //OS Internals
    alignas(CACHE_LINE_SIZE) inline const size_t NUM_THREADS = std::thread::hardware_concurrency();
    class Server : public SimpleServer {
        private:
            void accepter(HDE::AddressQueue& address_queue, quill::Logger* logger) override;
            void handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue, quill::Logger* logger) override;
            void responder(HDE::ResponderQueue& response, quill::Logger* logger) override;
            char buffer[MAX_BUFFER_SIZE] = {0};
            int new_socket;
            std::string html_file_path = "/Users/trangtran/Desktop/coding_files/a/Networking/Servers/html_templates/random.html";
            std::string main_page_template_cache;
            size_t main_page_template_cache_size;
            void load_cache(quill::Logger* logger);
        public:
            Server(quill::Logger* logger);
            void launch(quill::Logger* logger) override;
            inline void logClientInfo(const std::string_view processing_component, const std::string_view message, quill::Logger* logger) const;
    };
}

#endif
