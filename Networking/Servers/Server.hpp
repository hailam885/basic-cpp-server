#ifndef Server_hpp
#define Server_hpp

#include "SimpleServer.hpp"

//Server guide:

//Benchmarking: set logs to minimal, turn off all other apps, disable enable_DoS_protection if needed, and benchmark with 100K, 1M, or 10M requests.

//alignas() const/mutable constexpr inline static thread_local volatile friend (enum/class/) <datatype>

//Switching to linux might require refactoring of the entire code base.


//Requires MAJOR refactoring


struct Request;
struct Response;
struct RateLimiter {
    static constexpr size_t MAX_SIZE = 200;  // Max requests to track
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

struct RateLimitShard {
    alignas(CACHE_LINE_SIZE) std::mutex mutex;
    std::unordered_map<std::string, RateLimiter> limiters;
    char padding[CACHE_LINE_SIZE - sizeof(std::mutex) - sizeof(std::unordered_map<std::string, RateLimiter>)];
};

constexpr size_t NUM_RATE_LIMIT_SHARDS = 16;
inline RateLimitShard rate_limit_shards[NUM_RATE_LIMIT_SHARDS];

//1024 bytes
struct alignas(CACHE_LINE_SIZE * 8) serverStatus {
    serverStatus() = default;
    mutable std::mutex address_queue_mutex;
    mutable std::mutex responder_queue_mutex;
    mutable std::mutex address_cv_mutex;
    mutable std::mutex response_cv_mutex;
    mutable std::mutex r_e_m_mutex;
    mutable std::mutex init_mutex;
    mutable std::mutex clean_up_mutex;
    mutable std::mutex general_mutex;
    mutable std::mutex file_access_mutex;
    mutable std::mutex rate_limited_mutex;
    //the two atomic bools needs some padding
    std::atomic<bool> finished_initialization;
    std::atomic<bool> stop_server = false;
    char padding[8 * CACHE_LINE_SIZE - 2 * sizeof(std::atomic<bool>) - 10 * sizeof(std::mutex) /*Other future variables here*/];
};

struct ParsedRequest {
    std::string method;
    std::string path;
    std::string_view version;
    bool valid = false;
};

namespace HDE {
    //Only create an object is this enum ONCE
    enum logLevel : int {
        FULL = 3,
        DEFAULT = 2,
        DECREASED = 1,
        MINIMAL = 0
    };

    //classes HTTPParser, ResponseCache, PathValidator, HTTPValidator are for security reasons.
    class HTTPParser {
        public:
            static ParsedRequest parse_request_line(std::string_view request) noexcept;
            //for parsing full headers, might need later
            inline static std::unordered_map<std::string_view, std::string_view> parse_headers(std::string_view request) noexcept;
    };

    class ResponseCache {
        private:
            std::unordered_map<std::string, std::string> cache;
            mutable std::shared_mutex cache_mutex;
            std::string not_found_response;
            std::string public_root;
            std::vector<std::pair<std::string, std::string>> loaded_routes;
            inline static std::string_view get_content_type(std::string_view path) noexcept;
            constexpr inline void create_404_response(); //loads into not_found_html & not_found_response
        public:
            inline void load_static_files(const std::vector<std::pair<std::string, std::string>>& routes, quill::Logger* logger);
            inline std::string_view get_response(std::string_view path) const noexcept;
            inline std::optional<std::string> load_file_response(const std::string& file_path) const;
            inline bool reload_file(const std::string& path, const std::string& file_path, quill::Logger* logger);
            inline size_t reload_all_files(quill::Logger* logger);
            inline void clear_cache();
            inline size_t get_cache_size() const;
    };

    class PathValidator {
        public:
            inline static std::string sanitize_path(std::string_view raw_path) noexcept;
            inline static std::string url_decode(const std::string& str) noexcept;
            inline static int hex_to_int(char c) noexcept;
    };

    class HTTPValidator {
        public:
            inline static bool is_valid_method(std::string_view method) noexcept;
            inline static bool is_valid_version(std::string_view method) noexcept;
            inline static bool is_valid_request_line(std::string_view request) noexcept;
            inline static bool is_valid_size(size_t size) noexcept;
    };

    //in the future try to combine all configurations into a struct and pass into cpu for effective cache line usage.

    struct alignas(CACHE_LINE_SIZE) serverConfig {
        //All modified settings requires restart && recompilation, settings are hardcoded for performance.

        //              [ General ]

        int queueCount = 1000000; //                    queue before being accepted, recommended 100K+
        int PORT = 80; //                               port, default to 80 is the easiest to test
        int MAX_CONNECTIONS_PER_SECOND = 40; //         connections per seconds threshold before rejecting due to possible DoS
        int MAX_ADDRESS_QUEUE_SIZE = -1; //             -1 disables the limit
        int MAX_RESPONSES_QUEUE_SIZE = -1; //           -1 disables the limit
        const size_t MAX_BUFFER_SIZE = 30721; //        size in bytes, recommended to be 30K+ bytes, avoid too high (50K+)
        enum logLevel log_level = DECREASED; //           FULL / DEFAULT / DECREASED / MINIMAL
        bool disable_logging = false; //                Fully disables logging besides the start up and config checking logs
        bool disable_warnings = true; //                Disables some warnings
        //backlog count are in a/Networking/Sockets/ListeningSocket.hpp, change the variable "backlog"

        //              [ Performance ]

        //dev notes
        //Try to improve handler function efficiency. also the write() function in responder is extremely inefficient, look for faster and less overhead alternatives to the write() function.
        //if the acceper/handler/responder's thread count is 1, delete the thread_local in the variables before the infinite loops.

        int threadsForAccepter = 1; //                  minimum 1
        int threadsForHandler = 6; //                   minimum 1, process is computation heavy so allocate more threads
        int threadsForResponder = 1; //                 minimum 1
        int totalUsedThreads = threadsForAccepter + threadsForHandler + threadsForResponder;
        bool continuous_responses = true; //            true / false                halting before calling a thread, just put true
        int handler_responses_per_second = 200; //      >>practically useless<<
        int responder_responses_per_second = 200; //    >>practically useless<<
        bool IO_SYNCHONIZATION = false; //              true / false                stability / performance  (only if C code is present)
        int wait_before_notify_thread = 0; //           >>practically useless<<

        //              [ Security ]

        bool enable_DoS_protection = false; //          true / 
    };

    alignas(CACHE_LINE_SIZE) inline serverConfig server_config;

    //Put every single html/css/js
    //always include a slash before the file type i.e. /pdf, /img, /jpeg
    inline std::string server_dir = "/Users/trangtran/Desktop/coding_files/a/Networking/Servers";
    //file routes doesn't update, requires a restart to update
    inline std::vector<std::pair<std::string, std::string>> file_routes_list = {
        //HTML
        {"/", server_dir + "/html/index.html"},
        {"/admin", server_dir + "/html/control_panel.html"},
        {"/random", server_dir + "/html/path/random.html"},
        {"/randoma", server_dir + "/html/path/randoma.html"},
        {"/resources", server_dir + "/html/path/resources.html"},
        //CSS
        {"/css/index.css", server_dir + "/css/index.css"},
        {"/css/control_panel.css", server_dir + "/css/control_panel.css"},
        {"/css/path/random.css", server_dir + "/css/path/random.css"},
        {"/css/path/randoma.css", server_dir + "/css/path/randoma.css"},
        {"/css/path/resources.css", server_dir + "/css/path/resources.css"},
        //JS
        {"/js/index.js", server_dir + "/js/index.js"},
        {"/js/control_panel.js", server_dir + "/js/control_panel.js"},
        {"/js/path/random.js", server_dir + "/js/path/random.js"},
        {"/js/path/randoma.js", server_dir + "/js/path/randoma.js"},
        {"/js/path/resources.js", server_dir + "/js/path/resources.js"}
        //OTHERS
    };

    //DO NOT DELETE OR UNCOMMENT ANY OF THE COMMENTS THEY'RE THERE FOR A REASON

    //Performance monitoring

    struct alignas(CACHE_LINE_SIZE) ServerMetrics{
        std::atomic<uint64_t> total_requests{0};
        std::atomic<uint64_t> successful_requests{0};
        std::atomic<uint64_t> failed_requests{0};
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint64_t> bytes_received{0};
        std::chrono::steady_clock::time_point start_time;
        ServerMetrics() : start_time(std::chrono::steady_clock::now()) {};
        void record_request(bool success, size_t bytes_in, size_t bytes_out);
        std::string get_metrics_json() const;
    };

    struct AdminConfig {
        std::string_view admin_password = "lamtran1234";
        bool admin_enabled = true;
        const std::string admin_path_prefix = "/admin";
    };

    inline AdminConfig admin_config;

    class AdminAuth {
        public:
            static bool check_auth(std::string_view auth_header);
        private:
            static std::string base64_decode(std::string_view encoded);
    };

    //creating structs
    alignas(CACHE_LINE_SIZE * 8) inline serverStatus serverState;
    alignas(CACHE_LINE_SIZE) inline ServerMetrics server_metrics;

    //Server configurations
    //alignas(CACHE_LINE_SIZE) constexpr int queueCount = 10000000;
    //alignas(CACHE_LINE_SIZE) constexpr int Port = 80;
    //alignas(CACHE_LINE_SIZE) constexpr int MAX_CONNECTIONS_PER_SECOND = 40;

    //Performance settings, requires server recompilation + restart to take effect, configurations is hard-coded into server to achieve maximum performance.

    //Control memory usage lower -> less memory usage/buffer capacity; higher -> high memory usage/buffer capacity
    //alignas(CACHE_LINE_SIZE) constexpr int max_incoming_address_queue_size = 50000;
    //alignas(CACHE_LINE_SIZE) constexpr int max_responses_queue_size = 50000;

    //It is recommended to have the handler's thread count more than the accepter's and responder's thread count.
    //alignas(CACHE_LINE_SIZE) constexpr int threadsForAccepter = 2;
    //alignas(CACHE_LINE_SIZE) constexpr int threadsForHandler = 4;
    //alignas(CACHE_LINE_SIZE) constexpr int threadsForResponder = 2;
    //alignas(CACHE_LINE_SIZE) constexpr int totalUsedThreads = threadsForAccepter + threadsForHandler + threadsForResponder;

    //configures whether to limit the responder function from checking too much
    //delay is 1000 / handler_responses_per_second (miliseconds) before checking the queue.
    //alignas(CACHE_LINE_SIZE) constexpr bool continuous_responses = true;
    //alignas(CACHE_LINE_SIZE) inline int handler_responses_per_second = 200;
    //alignas(CACHE_LINE_SIZE) inline int responder_responses_per_second = 200;

    //This feature ensures thread-safe compatibility between C's printf and C++'s stream operator. When [false], unexpected behavior might occur (only if the program mixes between C/C++ code). true -> server stability; false -> increased performance
    //alignas(CACHE_LINE_SIZE) constexpr bool IOSynchronization = false;

    //Typically the accepter functions will notify a thread as soon as a request is available. The limit here is to wait before the queue size gets past a certain limit to notify a thread. DO NOT turn this on yet, we do not have enough people to queue up; the server will just not process them.
    //0 -> disabled, 1 -> limit by queue size, 2 -> limit by time
    //right now the wait_before_notify_thread is default to 0, changing it doesn't change anything.
    //alignas(CACHE_LINE_SIZE) constexpr int wait_before_notify_thread = 0;
    //alignas(CACHE_LINE_SIZE) constexpr int queue_size_limit_before_notify = 20;

    //Define the maximum limit in bytes a client's request can have; recommended to have 30000+.
    //alignas(CACHE_LINE_SIZE) constexpr size_t MAX_BUFFER_SIZE = 30721;

    //Logging Configurations
    //Even logLevel::MINIMAL logs still produces logs, it's just one line per client; and the logs checking for config errors are run on startup no matter what log_level is set to.
    //logLevel::FULL (Full & Debug Logs) / logLevel::DEFAULT / logLevel::DECREASED / logLevel::MINIMAL
    //alignas(CACHE_LINE_SIZE) constexpr enum logLevel log_level = MINIMAL;

    //Security Settings
    //alignas(CACHE_LINE_SIZE) constexpr bool enable_DoS_protection = false;

    //Server-side declarations here, do not modify anything below this line
    extern std::unordered_map<std::string, RateLimiter> connection_history;

    //Utility functions
    inline std::string_view get_current_time();
    void clean_server_shutdown(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue);
    inline void reportErrorMessage(quill::Logger* logger);
    bool is_rate_limited(const std::string_view client_ip);
    inline std::string_view get_thread_id_cached();

    //OS Internals
    alignas(CACHE_LINE_SIZE) inline const size_t NUM_THREADS = std::thread::hardware_concurrency();
    class Server : public SimpleServer {
        private:
            void accepter(HDE::AddressQueue& address_queue, quill::Logger* logger) override;
            void handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue, quill::Logger* logger) override;
            void responder(HDE::ResponderQueue& response, quill::Logger* logger) override;
            //char buffer[buffer_size] = {0};
            int new_socket;
            ResponseCache cache;
        public:
            Server(quill::Logger* logger);
            void launch(quill::Logger* logger) override;
            inline void logClientInfo(const std::string_view processing_component, const std::string_view message, quill::Logger* logger) const;
    };
}

#endif
