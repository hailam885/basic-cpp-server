#include "Server.hpp"
#include <iostream>
#include <pthread.h>
#include <sched.h>
//dev notes
//Developed for C++23.
/*
Performance optimization goals:
- consider switching to std::jthread
- consider switching to std::format; proven to be more efficient to C++ stream operator (<<)
- consider switching to std::span (or std::string_view); passes data buffers more efficiently/less overhead
- aggresively use constexpr and consteval for possible compile-time calculations
- use alignas to minimize cache line mises
- use padding of unusual size for different variables residing in different lines.
- use [[likely]] & [[unlikely]] to influence branch prediction on the most probable branch:
if () [[likely/unlikely]] {
    //something
} else [[likely/unlikely]] {
    //something
}
- use std::atomic with std::memory_order::relaxed for where order of operations relative to other threads does not matter
   -> when adding performance counters in the future, use std::memory_order_relaxed
- Protocol Buffers/FlatBuffers: use compact, binary serialization formats; ditch JSON/XML
- try to implement lock-free data structures using std::atomic (hard)
- consider using a small, fixed-size thread pool instead of creating/destroying threads for every request
- use std::condition_variable instead of polling to block worker threads, nearly zero-time
- If possible, try ditch the standard malloc/new and try custom high-frequency allocations like object pooling or arena allocators
- If possible, try using Profile-Guided Optimization (PGO); compiler looks at performance profile during runtime and perform runtime optimizations to the final binary
(Obscure)
- CPU Core Pinning: Pin certain server threads to specific physical cores; reducing time to move tasks around
[compiler] -fprofile-generate; ./a.out OR ./main; g++ -fprofile-use
- Configure OS to utilize large memory pages (2MB - 1GB) instead of the standard 4kB
- If possible, try allocating memory on the same physical memory bank attached to the CPU socket that will primarily use the data
- using a dedicated core to spin on a condition instead of using a blocking lock for extremely-low-latency situations
- try batch data together and process them all at once
- pass std::exeution::par as the first parameters of <algorithm> functions, C++17+ only.
*/

///only use PGO near the end of production/near feature-complete

/*
* LOCK HIERARCHY (always acquire in this order):
* 1. (removed)
* 2. rate_limited_mutex  
* 3. address_queue_mutex
* 4. responder_queue_mutex
* 5. file_access_mutex
* 
* Never acquire a higher-priority lock while holding a lower one
*/

//0x80000000 = 2147483648 -> -2147483647 (int)
//0x8000000000000000 = 9223372036854775808 -> -9223372036854775807 (long long int/64-bit)

//in the future, if possible create a struct for each of these mutexes/conditional variables and add padding; but only do it for frequently-accessed ones.
alignas(CACHE_LINE_SIZE) socklen_t addrlen = sizeof(struct sockaddr_in);

//definitions
//keep conditional variables separate; they might cause unexpected deadlocks
alignas(CACHE_LINE_SIZE) std::condition_variable finish_initialization;
alignas(CACHE_LINE_SIZE) std::condition_variable addr_in_addr_queue;
alignas(CACHE_LINE_SIZE) std::condition_variable resp_in_res_queue;

//for future attempts:     [Thread <thread id>]: [<timestamp>]: [<processing component, if possible>] [<message>]

//Main code, do not modify

//Utilities
inline std::string_view HDE::get_thread_id_cached() {
    thread_local std::string cached_id = []() {
        std::ostringstream oss;
        oss << std::this_thread::get_id();
        return oss.str();
    }();
    return cached_id;
}
//Thread-safe, gets the current time in a string; uses a cached-time system to save processing power
inline std::string_view HDE::get_current_time() {
    thread_local std::string cached_time;
    thread_local int64_t cached_second = 0;
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    int64_t current_second = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    if (current_second != cached_second) [[unlikely]] {
        std::time_t now_c = current_second;
        std::tm local_tm_struct;
        localtime_r(&now_c, &local_tm_struct);
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local_tm_struct);
        cached_time = buf;
        cached_second = current_second;
    }
    return cached_time;
}
//Thread safe
inline void HDE::Server::logClientInfo(const std::string_view processing_component, const std::string_view message, quill::Logger* logger) const {
    if (!message.empty() && HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) [[likely]] {
        LOG_INFO(logger, "[Thread {}]: [{}] logClientInfo(): {}", get_thread_id_cached(), processing_component, message);
    } else if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) [[unlikely]] {
        LOG_INFO(logger, "[Thread {}]: [{}] logClientInfo(): <empty>", get_thread_id_cached(), processing_component);
    } else {
        return;
    }
}
//Thread-safe, only prints if static_cast<int>(HDE::log_level) is set to anything higher than 0.
inline void HDE::reportErrorMessage(quill::Logger* logger) {
    int error_code = errno;
    if (HDE::server_config.log_level != MINIMAL) {
        LOG_ERROR(logger, "[Thread {}]: An error has occured (Description, if any, line above).", get_thread_id_cached());
    }
    if (errno == EINTR) [[unlikely]] {
        if (HDE::server_config.log_level != MINIMAL) LOG_ERROR(logger, "[Thread {}]: Message: A possible interrupted system call is detected.", get_thread_id_cached());
    } else if (errno == EMFILE || errno == ENFILE) [[unlikely]] {
        if (HDE::server_config.log_level != MINIMAL) LOG_ERROR(logger, "[Thread {}]: Message: The server is using a lot of resources (Too many open files). Check immediately.", get_thread_id_cached());
    } else if (HDE::server_config.log_level != MINIMAL) [[likely]] {
        LOG_ERROR(logger, "[Thread {}]: Message: {}", get_thread_id_cached(), strerror(errno));
    } else return;
}
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
//(Probably implemented in the future) Function will repeatedly try to add; and will wait for 
void HDE::AddressQueue::emplace_response(int loc, std::span<const char> data, quill::Logger* logger) {
    {
        std::scoped_lock<std::mutex> lock(HDE::serverState.address_queue_mutex);
        //have a wait condition here that waits until responder queue has space
        if (address_queue.size() < HDE::server_config.MAX_ADDRESS_QUEUE_SIZE || HDE::server_config.MAX_ADDRESS_QUEUE_SIZE == -1) [[likely]] {
            address_queue.emplace(loc, std::string(data.data(), data.size()));
        } else [[unlikely]] {
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_NOTICE(logger, "[Thread {}]: Rejecting client due to incoming_address_queue_size overflow. Overflow limit: {} clients.", get_thread_id_cached(), HDE::server_config.MAX_ADDRESS_QUEUE_SIZE);
            }
            return;
        }
        //while (true) {
            //
        //}
    }
    addr_in_addr_queue.notify_one();
}
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
void HDE::AddressQueue::emplace_response(const int location, const std::string_view msg, quill::Logger* logger) {
    {
        std::scoped_lock<std::mutex> lock(HDE::serverState.address_queue_mutex);
        //have a wait condition here that waits until responder queue has space
        if (address_queue.size() < HDE::server_config.MAX_ADDRESS_QUEUE_SIZE || HDE::server_config.MAX_ADDRESS_QUEUE_SIZE == -1) [[likely]] {
            address_queue.emplace(location, msg);
        } else [[unlikely]]  {
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_NOTICE(logger, "[Thread {}]: Rejecting client due to incoming_address_queue_size overflow. Overflow limit: {} clients.", get_thread_id_cached(), HDE::server_config.MAX_ADDRESS_QUEUE_SIZE);
            }
            return;
        }
    }
    addr_in_addr_queue.notify_one();
}
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
struct Request HDE::AddressQueue::get_response() {
    std::scoped_lock<std::mutex> lock(HDE::serverState.address_queue_mutex);
    if (!address_queue.empty()) [[likely]] {
        struct Request res = std::move(address_queue.front());
        address_queue.pop();
        return res; //Allow for RVO
    } else [[unlikely]] return Request{};
}
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
int HDE::AddressQueue::get_size() const noexcept {
    std::scoped_lock<std::mutex> lock(HDE::serverState.address_queue_mutex);
    return address_queue.size();
}
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
void HDE::AddressQueue::closeAllConnections() {
    std::vector<int> fds_to_close;
    {
        std::scoped_lock<std::mutex> lock(HDE::serverState.address_queue_mutex);
        while (!address_queue.empty()) {
            if (address_queue.front().location != -1) [[likely]] {
                fds_to_close.push_back(address_queue.front().location);
            }
            address_queue.pop();
        }
    }
    for (int fd : fds_to_close) {
        if (close(fd) < 0) [[unlikely]] {
            shutdown(fd, SHUT_RDWR);
        }
    }
}
//Thread-safe, alternate version for the closeAllConnections(), only recommended for 1000+ concurrent connections
/*void HDE::AddressQueue::closeAllConnections() noexcept(false) {
    std::vector<int> fds_to_close;
    {
        std::scoped_lock<std::mutex> lock(address_queue_mutex);
        fds_to_close.reserve(address_queue.size());
        
        while (!address_queue.empty()) {
            if (address_queue.front().location != -1) [[likely]] {
                fds_to_close.push_back(address_queue.front().location);
            }
            address_queue.pop();
        }
    }
    for (int fd : fds_to_close) {
        shutdown(fd, SHUT_RDWR);  // Non-blocking, just sends RST
    }
    for (int fd : fds_to_close) {
        try {
            close(fd);
        } catch (...) {
            // Already shutdown, ignore errors
        }
    }
}*/
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
bool HDE::AddressQueue::empty() const noexcept {
    std::scoped_lock<std::mutex> lock(HDE::serverState.address_queue_mutex);
    return address_queue.empty();
}
//will not add element if adding them means allResponses's size exceeds HDE::maxResponsesQueue.
//in the future if the website grows might switch [[likely]] with [[unlikely]]
/*void HDE::ResponderQueue::emplace_response(int loc, std::span<const char> data, quill::Logger* logger) noexcept {
    std::scoped_lock<std::mutex> lock(responder_queue_mutex);
    if (allResponses.size() <= HDE::max_responses_queue_size) [[likely]] {
        allResponses.emplace(loc, std::string(data.data(), data.size()));
        resp_in_res_queue.notify_one();
    } else [[unlikely]] {
        if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) LOG_INFO(logger, "[Thread {}]: Rejecting client due to max_responses_queue_size overflow; Overflow limit: {} clients.", get_thread_id_cached(), std::to_string(HDE::max_responses_queue_size));
    }
}*/
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
void HDE::ResponderQueue::emplace_response(const int destination, const std::string_view msg, quill::Logger* logger) {
    {
        std::scoped_lock<std::mutex> lock(HDE::serverState.responder_queue_mutex);
        if (allResponses.size() <= HDE::server_config.MAX_RESPONSES_QUEUE_SIZE || HDE::server_config.MAX_RESPONSES_QUEUE_SIZE == -1) [[likely]] {
            allResponses.emplace(destination, msg);
        } else [[unlikely]] {
            //have a wait condition here that waits until responder queue has space
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: Rejecting client due to max_responses_queue_size overflow; Overflow limit: {} clients.", get_thread_id_cached(), HDE::server_config.MAX_RESPONSES_QUEUE_SIZE);
            }
        }
        return;
    }
    resp_in_res_queue.notify_one();
}
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
struct Response HDE::ResponderQueue::get_response() noexcept {
    std::scoped_lock<std::mutex> lock(HDE::serverState.responder_queue_mutex);
    if (!allResponses.empty()) [[likely]] {
        struct Response destination = std::move(allResponses.front());
        allResponses.pop();
        return destination;
    } else [[unlikely]] return Response{};
}
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
int HDE::ResponderQueue::get_size() const noexcept {
    std::scoped_lock<std::mutex> lock(HDE::serverState.responder_queue_mutex);
    return allResponses.size();
}
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
void HDE::ResponderQueue::closeAllConnections() {
    std::vector<int> fds_to_close;
    {
        std::scoped_lock<std::mutex> lock(HDE::serverState.responder_queue_mutex);
        while (!allResponses.empty()) {
            if (allResponses.front().destination != -1) [[likely]] {
                fds_to_close.push_back(allResponses.front().destination);
            }
            allResponses.pop();
        }
    }
    for (int fd : fds_to_close) {
        if (close(fd) < 0) [[unlikely]] {
            shutdown(fd, SHUT_RDWR);
        }
    }
}
//Thread-safe, alternate version for the closeAllConnections(), only recommended for 1000+ concurrent connections
/*void HDE::AddressQueue::closeAllConnections() noexcept(false) {
    std::vector<int> fds_to_close;
    {
        std::scoped_lock<std::mutex> lock(responder_queue_mutex);
        fds_to_close.reserve(allResponses.size());
        
        while (!allResponses.empty()) {
            if (allResponses.front().destination != -1) [[likely]] {
                fds_to_close.push_back(allResponses.front().destination);
            }
            allResponses.pop();
        }
    }
    for (int fd : fds_to_close) {
        shutdown(fd, SHUT_RDWR);  // Non-blocking, just sends RST
    }
    for (int fd : fds_to_close) {
        try {
            close(fd);
        } catch (...) {
            // Already shutdown, ignore errors
        }
    }
}*/
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
bool HDE::ResponderQueue::empty() const noexcept {
    std::scoped_lock<std::mutex> lock(HDE::serverState.responder_queue_mutex);
    return allResponses.empty();
}

//Constructor
HDE::Server::Server(quill::Logger* logger) : SimpleServer(AF_INET, SOCK_STREAM, 0, HDE::server_config.PORT, INADDR_ANY, HDE::server_config.queueCount) {
    HDE::Server::launch(logger);
}

//probably not ever gonna use this function but don't delete it we might, and i say might need it in the future (no promises)
void HDE::clean_server_shutdown(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue) {
    HDE::serverState.stop_server.store(true, std::memory_order_seq_cst);
    address_queue.closeAllConnections();
    responder_queue.closeAllConnections();
    resp_in_res_queue.notify_all();
    addr_in_addr_queue.notify_all();
}
//Thread-safe
//I actually have no idea how this works
bool HDE::is_rate_limited(std::string_view client_ip) {
    size_t shard = std::hash<std::string_view>{}(client_ip) % NUM_RATE_LIMIT_SHARDS;
    auto& [mutex, limiters, _] = rate_limit_shards[shard];
    std::scoped_lock<std::mutex> lock(HDE::serverState.rate_limited_mutex);
    auto now = std::chrono::steady_clock::now();
    RateLimiter& limiter = limiters[std::string(client_ip)];
    size_t recent = limiter.count_recent(std::chrono::seconds(1));
    if (recent >= HDE::server_config.MAX_CONNECTIONS_PER_SECOND) [[unlikely]] return true;
    limiter.add(now);
    return false;
}

inline ParsedRequest HDE::HTTPParser::parse_request_line(std::string_view request) noexcept {
    ParsedRequest result;
    if (!HTTPValidator::is_valid_request_line(request)) [[unlikely]] return result; // result.valid = false
    size_t first_space = request.find(' ');
    if (first_space == std::string_view::npos || first_space == 0) [[unlikely]] return result;
    result.method = request.substr(0, first_space);
    if (!HTTPValidator::is_valid_method(result.method)) [[unlikely]] return result;
    size_t second_space = request.find(' ', first_space + 1);
    if (second_space == std::string_view::npos) [[unlikely]] return result;
    std::string_view raw_path = request.substr(first_space + 1, second_space - first_space - 1);
    std::string sanitized = PathValidator::sanitize_path(raw_path);
    if (sanitized.empty()) [[unlikely]] return result; //invalid path
    result.path = sanitized;
    size_t line_end = request.find("\r\n", second_space);
    if (line_end == std::string_view::npos) [[unlikely]] return result;
    result.version = request.substr(second_space + 1, line_end - second_space - 1);
    if (!HTTPValidator::is_valid_version(result.version)) [[unlikely]] return result;
    result.valid = true;
    return result;
}

inline std::unordered_map<std::string_view, std::string_view> HDE::HTTPParser::parse_headers(std::string_view request) noexcept {
    std::unordered_map<std::string_view, std::string_view> headers;
    size_t pos = request.find("\r\n");
    if (pos == std::string_view::npos) [[unlikely]] return headers;
    pos += 2;
    while (pos < request.size()) {
        size_t line_end = request.find("\r\n", pos);
        if (line_end == std::string_view::npos) [[unlikely]] return headers;
        std::string_view line = request.substr(pos, line_end - pos);
        if (line.empty()) break;
        size_t colon = line.find(':');
        if (colon != std::string_view::npos) {
            std::string_view key = line.substr(0, colon);
            std::string_view value = line.substr(colon + 1);
            while (!value.empty() && value[0] == ' ') value.remove_prefix(1);
            headers[key] = value;
        }
        pos = line_end + 2;
    }
    return headers;
}

inline std::optional<std::string> HDE::ResponseCache::load_file_response(const std::string& file_path) const {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) [[unlikely]] return std::nullopt;
    auto size = file.tellg();
    if (size <= 0) [[unlikely]] file.close(); return std::nullopt;
    file.seekg(0);
    std::string content;
    content.resize(size);
    file.read(content.data(), size);
    file.close();
    std::string_view content_type = HDE::ResponseCache::get_content_type(file_path);
    return std::format(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"           // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                     // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"           // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n{}",
        content_type, size, content
    );
}

inline void HDE::ResponseCache::load_static_files(const std::vector<std::pair<std::string, std::string>>& routes, quill::Logger* logger) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
    loaded_routes = routes;
    for (const auto& [url_path, file_path] : routes) {
        auto response_opt = load_file_response(file_path);
        if (!response_opt.has_value()) [[unlikely]] {
            LOG_ERROR(logger, "WARNING: Cannot load file: {} for URL: {}", file_path, url_path);
            continue;
        } 
        cache[url_path] = std::move(response_opt.value());
        LOG_INFO(logger, "Mapped: {} → {} ({} bytes)", url_path, file_path, cache[url_path].length());
    }
    
    create_404_response();
    LOG_INFO(logger, "Loaded {} custom routes", cache.size());
}

inline std::string_view HDE::ResponseCache::get_response(std::string_view path) const noexcept {
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
    // 1. Try exact path match first
    auto it = cache.find(std::string(path));
    if (it != cache.end()) [[likely]] {
        return it->second;
    }
    // 2. If path is "/", try "/index.html"
    if (path == "/") [[unlikely]] {
        it = cache.find("/index.html");
        if (it != cache.end()) {
            return it->second;
        }
    }
    // 3. If path is directory (ends with /), try appending "index.html"
    if (path.size() > 1 && path.back() == '/') [[unlikely]] {
        std::string index_path = std::string(path) + "index.html";
        it = cache.find(index_path);
        if (it != cache.end()) {
            return it->second;
        }
    }
    // 4. Return 404
    return not_found_response;
}

inline bool HDE::ResponseCache::reload_file(const std::string& path, const std::string& file_path, quill::Logger* logger) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) [[unlikely]] return std::nullopt;
    auto size = file.tellg();
    if (size <= 0) [[unlikely]] file.close(); return std::nullopt;
    file.seekg(0);
    std::string content;
    content.resize(size);
    file.read(content.data(), size);
    file.close();
    std::string_view content_type = HDE::ResponseCache::get_content_type(file_path);
    std::string response = std::format(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"           // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                     // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"           // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n{}",
        content_type, size, content
    );
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
    cache[path] = std::move(response);
    LOG_INFO(logger, "Reloaded: {}", path);
    return true;
}

inline std::string_view HDE::ResponseCache::get_content_type(std::string_view path) noexcept {
    size_t dot_pos = path.rfind('.');
    if (dot_pos == std::string_view::npos) return "application/octet-stream";
    std::string_view ext = path.substr(dot_pos);
    if (ext == ".html" || ext == ".htm") return "text/html; charset=utf-8";
    if (ext == ".css") return "text/css; charset=utf-8";
    if (ext == ".js") return "application/javascript; charset=utf-8";
    if (ext == ".json") return "application/json; charset=utf-8";
    if (ext == ".xml") return "application/xml; charset=utf-8";
    if (ext == ".png") return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".gif") return "image/gif";
    if (ext == ".svg") return "image/svg+xml";
    if (ext == ".webp") return "image/webp";
    if (ext == ".ico") return "image/x-icon";
    if (ext == ".woff") return "font/woff";
    if (ext == ".woff2") return "font/woff2";
    if (ext == ".ttf") return "font/ttf";
    if (ext == ".otf") return "font/otf";
    if (ext == ".pdf") return "application/pdf";
    if (ext == ".zip") return "application/zip";
    if (ext == ".txt") return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

constexpr inline void HDE::ResponseCache::create_404_response() {
    std::string not_found_html = 
        "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
        "<body><h1>404 Not Found</h1>"
        "<p>The requested resource does not exist.</p></body></html>";
    
    not_found_response = std::format(
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"           // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                     // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"           // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n{}",
        not_found_html.length(), not_found_html
    );
}

inline size_t HDE::ResponseCache::reload_all_files(quill::Logger* logger) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
    size_t count = 0;
    for (const auto& [url_path, file_path] : loaded_routes) {
        auto response_opt = load_file_response(file_path);
        if (response_opt.has_value()) {
            cache[url_path] = std::move(response_opt.value());
            count++;
            LOG_INFO(logger, "Reloaded: {}", url_path);
        }
    }
    return count;
}

inline void HDE::ResponseCache::clear_cache() {
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
    cache.clear();
    create_404_response();
}
inline size_t HDE::ResponseCache::get_cache_size() const {
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
    return cache.size();
}

inline void HDE::ServerMetrics::record_request(bool success, size_t bytes_in, size_t bytes_out) {
    total_requests.fetch_add(1, std::memory_order_relaxed);
    if (success) {
        successful_requests.fetch_add(1, std::memory_order_relaxed);
    } else {
        failed_requests.fetch_add(1, std::memory_order_relaxed);
    }
    bytes_received.fetch_add(bytes_in, std::memory_order_relaxed);
    bytes_sent.fetch_add(bytes_out, std::memory_order_relaxed);
}

inline std::string HDE::ServerMetrics::get_metrics_json() const {
    auto uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time).count();
    uint64_t total = total_requests.load(std::memory_order_relaxed);
    uint64_t success = successful_requests.load(std::memory_order_relaxed);
    uint64_t failed = failed_requests.load(std::memory_order_relaxed);
    uint64_t bytes_in = bytes_received.load(std::memory_order_relaxed);
    uint64_t bytes_out = bytes_sent.load(std::memory_order_relaxed);
    double req_per_sec = uptime_seconds > 0 ? static_cast<double>(total) / uptime_seconds : 0.0; //change the implementation; it displays the mean overtime, not the quite current requests per second
    return std::format(
        "{{\n"
        "  \"uptime_seconds\": {},\n"
        "  \"total_requests\": {},\n"
        "  \"successful_requests\": {},\n"
        "  \"failed_requests\": {},\n"
        "  \"bytes_received\": {},\n"
        "  \"bytes_sent\": {},\n"
        "  \"requests_per_second\": {:.2f},\n"
        "  \"cache_size\": {},\n"
        "  \"thread_count\": {}\n"
        "}}",
        uptime_seconds, total, success, failed, bytes_in, bytes_out, req_per_sec, 0, HDE::server_config.totalUsedThreads
    );
}

inline bool HDE::AdminAuth::check_auth(std::string_view auth_header) {
    if (auth_header.empty()) return false;
    if (!auth_header.starts_with("Basic ")) return false;
    std::string_view encoded = auth_header.substr(6);
    std::string decoded = base64_decode(encoded);
    size_t colon = decoded.find(':');
    if (colon == std::string::npos) return false;
    std::string password = decoded.substr(colon + 1);
    return password == admin_config.admin_password;
}

inline std::string HDE::AdminAuth::base64_decode(std::string_view encoded) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    std::vector<int> vec(256, -1);
    for (int i = 0; i < 64; i++) vec[base64_chars[i]] = i;
    int val = 0, bits = -8;
    for (unsigned char c : encoded) {
        if (vec[c] == -1) break;
        val = (val << 6) + vec[c];
        bits += 6;
        if (bits >= 0) {
            decoded.push_back(char((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return decoded;
}

inline std::string HDE::PathValidator::sanitize_path(std::string_view raw_path) noexcept {
    if (raw_path.empty() || raw_path[0] != '/') [[unlikely]] return "";
    std::string path(raw_path);
    size_t query_pos = path.find('?');
    if (query_pos != std::string::npos) path = path.substr(0, query_pos);
    size_t fragment_pos = path.find('#');
    if (fragment_pos != std::string::npos) path = path.substr(0, fragment_pos);
    path = url_decode(path);
    if (path.find("..") != std::string::npos) [[unlikely]] return "";
    if (path.find("//") != std::string::npos) [[unlikely]] return "";
    if (path.find('\0') != std::string::npos) [[unlikely]] return ""; // Null byte injection (could truncate strings in C APIs)
    if (path.size() > 1 && path[1] == ':') [[unlikely]] return ""; // Check for absolute path attempts
    if (path.length() > 2048) [[unlikely]] return ""; // Limit path length
    for (char c : path) if (!std::isalnum(c) && c != '/' && c != '-' && c != '_' && c != '.') [[unlikely]] return ""; // Invalid character - REJECT
    return path;
}

inline std::string HDE::PathValidator::url_decode(const std::string& str) noexcept {
    std::string result;
    result.reserve(str.length());
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int high = hex_to_int(str[i + 1]);
            int low = hex_to_int(str[i + 2]);
            if (high != -1 && low != -1) {
                result += static_cast<char>((high << 4) | low);
                i += 2;
                continue;
            }
        } else if (str[i] == '+') {
            result += ' ';
            continue;
        }
        result += str[i];
    }
    return result;
}

inline int HDE::PathValidator::hex_to_int(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

inline bool HDE::HTTPValidator::is_valid_method(std::string_view method) noexcept {
    return method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "POST";
}

inline bool HDE::HTTPValidator::is_valid_version(std::string_view version) noexcept {
    return version == "HTTP/1.1" || version == "HTTP/1.0";
}

inline bool HDE::HTTPValidator::is_valid_request_line(std::string_view request) noexcept {
    if (request.find("\r\n") == std::string_view::npos) [[unlikely]] return false;
    if (request.find('\0') != std::string_view::npos) [[unlikely]] return false;
    size_t first_line_end = request.find("\r\n");
    size_t headers_end = request.find("\r\n\r\n");
    // If there's content after headers without Content-Length, suspicious
    if (headers_end != std::string_view::npos) {
        std::string_view after_headers = request.substr(headers_end + 4);
        if (!after_headers.empty() && request.find("Content-Length:") == std::string_view::npos) [[unlikely]] return false;
    }
    return true;
}

inline bool HDE::HTTPValidator::is_valid_size(size_t size) noexcept {
    return size >= 0 && size <= 65536;
}

//Runs on independent thread
void HDE::Server::accepter(HDE::AddressQueue& address_queue, quill::Logger* logger) {
    std::unique_lock<std::mutex> init_lock(HDE::serverState.init_mutex);
    std::unique_lock<std::mutex> addr_lock(HDE::serverState.address_queue_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [] {
        return HDE::serverState.finished_initialization.load(std::memory_order_acquire);
    });
    LOG_NOTICE(logger, "[Thread {}]: [Accepter] Initializing...", get_thread_id_cached());
    init_lock.unlock();
    char local_buf[HDE::server_config.MAX_BUFFER_SIZE];
    thread_local char ip_str[INET6_ADDRSTRLEN];
    thread_local int client_socket_fd;
    thread_local const size_t MAX_PACKET_SIZE = HDE::server_config.MAX_BUFFER_SIZE - 1;
    thread_local int res;
    thread_local int nodelay = 1;
    thread_local ssize_t bytesRead;
    thread_local struct timeval timeout;
    timeout.tv_sec = 5; //wait 5 seconds for client to send a response, closes when unresponsive
    timeout.tv_usec = 0;
    //Epoll set up, good for batching requests then process at once, but it's only good for managing hundreds/thousands of concurrent connections.
    /*#ifdef __APPLE__
        int kq = kqueue();
        if (kq < 0) {
            perror("Kqueue failed.");
            return;
        }
        struct kevent ev;
        EV_SET(&ev, get_socket()->get_sock(), EVFILT_READ, EV_ADD, 0, 0, nullptr);
        kevent(kq, &ev, 1, nullptr, 0, nullptr);
    #elif __linux__
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1) {
            perror("Kqueue failed.");
            return;
        }
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = get_socket()->get_sock();
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, get_socket()->get_sock(), &ev);
    #endif*/
    for (;;) {
        //Blocking accept() for 1 second
        /*#ifdef __linux__
            struct epoll_event events[1];
            int nfds = epoll_wait(epoll_fd, events, 1, 2000); //2 seconds timeout
            if (nfds > 0) client_socket_fd = accept(get_socket() -> get_sock(), reinterpret_cast<struct sockaddr*>(&address), reinterpret_cast<socklen_t*>(&addrlen));
        #elif __APPLE__
            struct kevent ev_list[10];
            struct timespec timeout = {2, 0};  // 2 seconds timeout
            int nev = kevent(kq, nullptr, 0, ev_list, 1, &timeout);
            if (nev < 0) [[unlikely]] {
                perror("Kevent wait");
                break;
            }
            if (nev == 0) {
                if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) [[unlikely]] LOG_INFO(logger, "[Thread {}]: [Accepter] No activity in 5 seconds.", get_thread_id_cached());
                continue;
            }
            for (int i = 0; i < nev; ++i) {
                if (ev_list[i].ident == get_socket() -> get_sock()) {
                    //New connection, push back client into the queue
                    address = get_socket() -> get_address();
                    socklen_t addrlen = sizeof(address);
                    if (nev > 0) client_socket_fd = accept(get_socket() -> get_sock(), reinterpret_cast<struct sockaddr*>(&address), &addrlen);
                } else {
                    //existing client, process client here
                    client_socket_fd = ev_list[i].ident;
                }
            }
        #endif*/
        if (HDE::serverState.stop_server.load(std::memory_order_relaxed)) [[unlikely]] break;
        if (HDE::server_config.log_level != MINIMAL) {
            LOG_INFO(logger, "[Thread {}]: [Accepter] Waiting for requests...", get_thread_id_cached());
        }
        struct sockaddr_in address = get_socket() -> get_address();
        client_socket_fd = accept(get_socket() -> get_sock(), reinterpret_cast<struct sockaddr*>(&address), reinterpret_cast<socklen_t*>(&addrlen));
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Accepter] Checkpoint 1 reached.", get_thread_id_cached());
        }
        if (client_socket_fd < 0) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) LOG_ERROR(logger, "[Thread {}]: [Accepter] A client cannot connect to the server.", get_thread_id_cached());
            HDE::reportErrorMessage(logger);
            continue;
        }
        if (setsockopt(client_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) [[unlikely]] {
            if (HDE::server_config.log_level == FULL) {
                LOG_NOTICE(logger, "[Accepter] Failed to set socket timeout");
            }
        }
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Accepter] Checkpoint 2 reached.", get_thread_id_cached());
        }
        if (setsockopt(client_socket_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0) { //send packets immediately when available configuration
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] Failed to set TCP_NODELAY", get_thread_id_cached());
            }
        }
        res = getnameinfo(reinterpret_cast<struct sockaddr*>(&address), sizeof(address), ip_str, INET6_ADDRSTRLEN, nullptr, 0, NI_NUMERICHOST);
        if (res != 0) [[unlikely]] {
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] A client has an unknown IP address. The server will attempt to close the connection; and shuts it down if that fails.", get_thread_id_cached());
            }
            HDE::reportErrorMessage(logger);
            if (close(client_socket_fd) < 0) [[unlikely]] {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Accepter] Checkpoint 3 reached.", get_thread_id_cached());
        }
        if (HDE::is_rate_limited(std::string(ip_str)) && HDE::server_config.enable_DoS_protection) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] Deteched possible DoS attempt from client {}. The server will attempt to close the connection, and shuts it if that fails.", get_thread_id_cached(), ip_str);
            }
            if (close(client_socket_fd) < 0) [[unlikely]] {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        bytesRead = read(client_socket_fd, local_buf, sizeof(local_buf) - 1);
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Accepter] Checkpoint 4 reached.", get_thread_id_cached());
        }
        if (bytesRead > 0 && bytesRead < sizeof(local_buf) - 1) [[likely]] {
            local_buf[bytesRead] = '\0'; //null terminator
            if (HDE::server_config.log_level == FULL) {
                LOG_DEBUG(logger, "[Thread {}]: [Accepter] About to acquire address_queue_mutex in .emplate_response()", get_thread_id_cached());
            }
            address_queue.emplace_response(client_socket_fd, std::span(local_buf, bytesRead), logger);
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_DEBUG(logger, "[Thread {}]: [Accepter] Received data from {}:\n{}", get_thread_id_cached(), ip_str, std::string(local_buf));
            } else if (HDE::server_config.log_level == DECREASED) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] Client {} is connected.", get_thread_id_cached(), ip_str);
            }
            continue;
        } else if (bytesRead == 0) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] A client is disconnected to the server. No bytes are read. IP: {}. The server will attempt to close the connection, and shuts it down if that fails.", get_thread_id_cached(), ip_str);
            }
            HDE::reportErrorMessage(logger);
            if (close(client_socket_fd) < 0) [[unlikely]] {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        } else if (bytesRead >= sizeof(local_buf) - 1) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] A client has a packet that could trigger a buffer overflow, either by an oversized request or a DoS attempt. Client IP: {}. Request size: {}. The server will attempt to close the connection, and shuts it down if that fails.", HDE::get_thread_id_cached(), ip_str, bytesRead);
            }
            if (close(client_socket_fd) < 0) [[unlikely]] {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) [[unlikely]] {
                if (HDE::server_config.log_level != MINIMAL) {
                    LOG_NOTICE(logger, "[Thread {}]: [Accepter] Socket read timeout - possible Slowloris attack. The server will attempt to close the connection, and shuts it down if that fails.", HDE::get_thread_id_cached());
                }
                if (close(client_socket_fd) < 0) [[unlikely]] {
                    shutdown(client_socket_fd, SHUT_RDWR);
                }
                continue;
            }
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] General read error encountered. The server will attempt to close the connection, and shuts it down if that fails.", HDE::get_thread_id_cached());
            }
            HDE::reportErrorMessage(logger);
            if (close(client_socket_fd) < 0) [[unlikely]] {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        if (HDE::connection_history.size() > 1000000) {
            connection_history.clear();
        }
    }
    /*#ifdef __APPLE__
        close(kq);
    #elif __linux__
        close(epoll_fd);
    #endif*/
    LOG_NOTICE(logger, "[Thread {}]: [Accepter] Accepter loop terminated.", get_thread_id_cached());
    return;
}
//Runs on independent thread
//Retrieve the incoming request from AddressQueue object, then load the processed request into the ResponderQueue object
//Function is computation-heavy, allocate more threads
void HDE::Server::handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue, quill::Logger* logger) {
    std::unique_lock<std::mutex> init_lock(HDE::serverState.init_mutex);
    std::unique_lock<std::mutex> addr_lock(HDE::serverState.address_queue_mutex, std::defer_lock);
    std::unique_lock<std::mutex> resp_lock(HDE::serverState.responder_queue_mutex, std::defer_lock);
    std::unique_lock<std::mutex> cv_lock(HDE::serverState.address_cv_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [] { 
        return HDE::serverState.finished_initialization.load(std::memory_order_acquire);
    });
    LOG_NOTICE(logger, "[Thread {}]: [Handler] Initializing...", get_thread_id_cached());
    init_lock.unlock();
    thread_local std::string temp;
    thread_local struct Request client;
    thread_local static const std::string_view bad_request_response = 
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 11\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n"
        "Bad Request";
    thread_local static const std::string_view forbidden_response = 
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 9\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n"
        "Forbidden";
    thread_local static const std::string_view method_not_allowed_response = 
        "HTTP/1.1 405 Method Not Allowed\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 18\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n"
        "Method Not Allowed";
    thread_local static const std::string_view unauthorized_response = 
        "HTTP/1.1 401 Unauthorized\r\n"
        "Content-Type: text/plain\r\n"
        "WWW-Authenticate: Basic realm=\"Admin Area\"\r\n"
        "Content-Length: 12\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n"
        "Unauthorized";
    for (;;) {
        if (HDE::serverState.stop_server.load(std::memory_order_relaxed)) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [Handler] Terminating handler loop...", get_thread_id_cached());
            address_queue.closeAllConnections();
            responder_queue.closeAllConnections();
            break;
        }
        if (HDE::server_config.log_level != MINIMAL) {
            LOG_INFO(logger, "[Thread {}]: [Handler] Waiting for tasks...", get_thread_id_cached());
        }
        {
            if (HDE::server_config.log_level == FULL) {
                LOG_DEBUG(logger, "[Thread {}]: [Handler] Acquired address_cv_mutex", get_thread_id_cached());
            }
            cv_lock.lock();
            addr_in_addr_queue.wait(cv_lock, [&address_queue] {
                return HDE::serverState.stop_server.load(std::memory_order_seq_cst) || !address_queue.empty();
            });
            cv_lock.unlock();
        }
        if (HDE::serverState.stop_server.load(std::memory_order_seq_cst)) [[unlikely]] continue;
        //calling get_response() without the lock; double locking causes a deadlock
        if (HDE::server_config.log_level == FULL) {
            LOG_DEBUG(logger, "[Thread {}]: [Handler] (checkpoint)", get_thread_id_cached());
        }
        client = address_queue.get_response();
        if (client.location == 0) [[unlikely]] continue;
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Handler] Checkpoint 1 reached.", get_thread_id_cached());
        }
        HDE::Server::logClientInfo("Handler", client.msg, logger);
        //<-- Server processing steps -->
        if (!HTTPValidator::is_valid_size(client.msg.length())) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [Handler] Suspicious request size: {} bytes", get_thread_id_cached(), client.msg.length());
            }
            responder_queue.emplace_response(client.location, bad_request_response, logger);
            resp_in_res_queue.notify_one();
            continue;
        }
        ParsedRequest parsed = HTTPParser::parse_request_line(client.msg);
        if (!parsed.valid) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [Handler] Invalid/malicious request detected from fd {}", get_thread_id_cached(), client.location);
            }
            responder_queue.emplace_response(client.location, bad_request_response, logger);
            resp_in_res_queue.notify_one();
            continue;
        }
        if (parsed.method != "GET" && parsed.method != "HEAD" && parsed.method != "POST") [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [Handler] Method not allowed: {}", get_thread_id_cached(), parsed.method);
            }
            responder_queue.emplace_response(client.location, method_not_allowed_response, logger);
            resp_in_res_queue.notify_one();
            continue;
        }
        if (parsed.path.starts_with("/admin")) [[unlikely]] {
            auto headers = HTTPParser::parse_headers(client.msg);
            auto auth_it = headers.find("Authorization");
            if (!admin_config.admin_enabled || (auth_it == headers.end() || !AdminAuth::check_auth(auth_it -> second))) {
                responder_queue.emplace_response(client.location, unauthorized_response, logger);
                resp_in_res_queue.notify_one();
                server_metrics.record_request(false, client.msg.length(), unauthorized_response.length());
                continue;
            }
            std::string response;
            if (parsed.path == "/admin" || parsed.path == "/admin/") {
                response = cache.get_response("/admin/control_panel.html");
            } else if (parsed.path == "/admin/metrics") {
                // Return metrics JSON
                std::string metrics_json = server_metrics.get_metrics_json();
                std::string metrics_response = std::format(
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: {}\r\n"
                    "Connection: close\r\n"
                    "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
                    "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
                    "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
                    "Content-Security-Policy: default-src 'self'\r\n"  // CSP
                    "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
                    "\r\n{}",
                    metrics_json.length(), metrics_json
                );
                responder_queue.emplace_response(client.location, metrics_response, logger);
                resp_in_res_queue.notify_one();
                if (HDE::server_config.continuous_responses) [[likely]] continue;
                else [[unlikely]] {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000 / HDE::server_config.handler_responses_per_second));
                    continue;
                }
            } else if (parsed.path == "/admin/cache/reload" && parsed.method == "POST") {
                // Reload cache
                cache.clear_cache();
                cache.load_static_files(HDE::file_routes_list, logger);
                size_t count = cache.reload_all_files(logger);
                std::string result_json = std::format("{{\"files_loaded\": {}}}", count);
                std::string reload_response;
                reload_response = std::format(
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: {}\r\n"
                    "Connection: close\r\n"
                    "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
                    "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
                    "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
                    "Content-Security-Policy: default-src 'self'\r\n"  // CSP
                    "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
                    "\r\n{}",
                    result_json.length(), result_json
                );
                LOG_INFO(logger, "[Thread {}]: [Handler] <Reload Cache> Response: {}", HDE::get_thread_id_cached(), reload_response);
                responder_queue.emplace_response(client.location, reload_response, logger);
                resp_in_res_queue.notify_one();
                if (HDE::server_config.continuous_responses) [[likely]] continue;
                else [[unlikely]] {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000 / HDE::server_config.handler_responses_per_second));
                    continue;
                }
            } else if (parsed.path == "/admin/cache/clear" && parsed.method == "POST") {
                // Clear cache
                cache.clear_cache();
                std::string result_json = "{\"status\": \"cleared\"}";
                std::string clear_response = std::format(
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: {}\r\n"
                    "Connection: close\r\n"
                    "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
                    "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
                    "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
                    "Content-Security-Policy: default-src 'self'\r\n"  // CSP
                    "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
                    "\r\n{}",
                    result_json.length(), result_json
                );
                responder_queue.emplace_response(client.location, clear_response, logger);
                resp_in_res_queue.notify_one();
                if (HDE::server_config.continuous_responses) [[likely]] continue;
                else [[unlikely]] {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000 / HDE::server_config.handler_responses_per_second));
                    continue;
                }
            } else if (parsed.path == "/admin/shutdown" && parsed.method == "POST") {
                LOG_CRITICAL(logger, "[Handler] Shutdown requested from admin panel");
                // Send response first
                std::string shutdown_json = "{\"status\": \"shutting_down\"}";
                std::string shutdown_response = std::format(
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: {}\r\n"
                    "Connection: close\r\n"
                    "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
                    "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
                    "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
                    "Content-Security-Policy: default-src 'self'\r\n"  // CSP
                    "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
                    "\r\n{}",
                    shutdown_json.length(), shutdown_json
                );
                responder_queue.emplace_response(client.location, shutdown_response, logger);
                resp_in_res_queue.notify_one();
                // Trigger shutdown after a delay
                std::thread([&address_queue, &responder_queue]() {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    HDE::clean_server_shutdown(address_queue, responder_queue);
                }).detach();
                continue;
            } else {
                // Admin endpoint not found
                response = cache.get_response(parsed.path);
            }
        }
        if (HDE::server_config.log_level == FULL) {
            LOG_INFO(logger, "[Thread {}]: [Handler] Valid request: {} {}", get_thread_id_cached(), parsed.method, parsed.path);
        }
        std::string_view response = cache.get_response(parsed.path);
        // <-- End server processing steps zone -->
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Handler] Checkpoint 2 reached.", get_thread_id_cached());
        }
        responder_queue.emplace_response(client.location, response, logger);
        resp_in_res_queue.notify_one();
        bool is_404 = response.starts_with("HTTP/1.1 404");
        server_metrics.record_request(!is_404, client.msg.length(), response.length());
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Handler] Checkpoint 3 reached.", get_thread_id_cached());
        }
        if (HDE::server_config.continuous_responses) [[likely]] continue;
        else [[unlikely]] {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / HDE::server_config.handler_responses_per_second));
            continue;
        }
    }
    LOG_NOTICE(logger, "[Thread {}]: [Handler] Handler loop terminated.", get_thread_id_cached());
    return;
}
//Runs on independent thread
void HDE::Server::responder(HDE::ResponderQueue& response, quill::Logger* logger) {
    std::unique_lock<std::mutex> init_lock(HDE::serverState.init_mutex);
    std::unique_lock<std::mutex> cv_lock(HDE::serverState.response_cv_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [] {
        return HDE::serverState.finished_initialization.load(std::memory_order_acquire);
    });
    LOG_NOTICE(logger, "[Thread {}]: [Responder] Initializing...", get_thread_id_cached());
    init_lock.unlock();
    thread_local struct Response client;
    thread_local const char* msg;
    thread_local ssize_t res;
    for (;;) {
        if (HDE::serverState.stop_server.load(std::memory_order_relaxed)) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [Responder] Terminating responder loop...", get_thread_id_cached());
            response.closeAllConnections();
            break;
        }
        {
            if (HDE::server_config.log_level == FULL) LOG_DEBUG(logger, "[Thread {}]: [Responder] Acquired responder_cv_mutex", get_thread_id_cached());
            if (HDE::server_config.log_level != MINIMAL) LOG_NOTICE(logger, "[Thread {}]: [Responder] Waiting for tasks...", get_thread_id_cached());
            cv_lock.lock();
            resp_in_res_queue.wait(cv_lock, [&response] {
                return HDE::serverState.stop_server.load(std::memory_order_acquire) || !response.empty();
            });
            cv_lock.unlock();
        }
        if (HDE::serverState.stop_server.load(std::memory_order_seq_cst)) [[unlikely]] continue;
        client = response.get_response();
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Responder] Checkpoint 1 reached.", get_thread_id_cached());
        }
        if (client == Response{}) [[unlikely]] continue;
        msg = client.msg.c_str();
        if (HDE::server_config.log_level != MINIMAL) {
            LOG_INFO(logger, "[Thread {}]: [Responder] Received data from [Handler]. Processing...", get_thread_id_cached());
        }
        //In the future implement a loop here that keeps track of bytes being sent, then repeatedly spamming packets until remaining bytes = 0
        res = send(client.destination, msg, client.msg.length(), MSG_NOSIGNAL);
        if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
            LOG_INFO(logger, "[Thread {}]: [Responder] Result of variable <res>: {}", get_thread_id_cached(), std::to_string(res));
        }
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Responder] Checkpooint 2 reached.", get_thread_id_cached());
        }
        if (res < 0) [[unlikely]] {
            //case where the server failed to send the message
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_ERROR(logger, "[Thread {}]: [Responder] ERROR: A client failed to receive the data.", get_thread_id_cached());
            }
            //try to clean this in the future
            int error_code = errno;
            if (error_code == EAGAIN || error_code == EWOULDBLOCK) [[unlikely]] { //In the future the server might ran out of resources easily, so if possible change [[unlikely]] to [[likely]].
                if (HDE::server_config.log_level == FULL) {
                    LOG_NOTICE(logger, "[Thread {}]: [Responder] The kernel's socket sending buffer is full, try writing again later. Continuously trying again the write() will be implemented in the future (not near).", get_thread_id_cached());
                }
                continue;
            } else if (error_code == EPIPE) [[unlikely]] {
                if (HDE::server_config.log_level == FULL) {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] The socket has been closed by the client while transmission is happening.", get_thread_id_cached());
                }
                continue;
            } else if (error_code == ECONNRESET) [[likely]] {
                if (HDE::server_config.log_level == FULL) {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] The connection is reset by the peer. It could be an abrupt shut down or sent a TCP reset packet.", get_thread_id_cached());
                }
                continue;
            } else if (error_code == ETIMEDOUT) [[unlikely]] {
                if (HDE::server_config.log_level == FULL) {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] A network time out happened during transmission.", get_thread_id_cached());
                }
                continue;
            } else if (error_code == EBADF) [[unlikely]] {
                if (HDE::server_config.log_level == FULL) {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] The file is invalid; it has either been closed or never opened, or another unknown issue.", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            } else if (error_code == EINVAL) [[unlikely]] {
                if (HDE::server_config.log_level == FULL) {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] The file is valid but is not available for transission.", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            } else if (error_code == EINTR) [[unlikely]] {
                if (HDE::server_config.log_level == FULL) {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] The socket has been closed by the client while transmission is happening, or an interrupted system call (normally I.S.Cs are usually harmless). Restarting the write function would be the way to go; implementing a loop to continuosly try the write() in the future (not near).", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            } else if (error_code == ENOMEM) [[unlikely]] {
                if (HDE::server_config.log_level == FULL) {
                    LOG_CRITICAL(logger, "[Thread {}]: [Responder] The server ran out of memory trying to complete the request. Either there being not enough memory (while creating internal structures), or this is a sign of a possible attack.", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            } else [[likely]] {
                if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                    LOG_CRITICAL(logger, "[Thread {}]: [Responder] An undocumented error occured.", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            }
        } else if (res > 0) [[likely]] {
            //successful tramission
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_INFO(logger, "[Thread {}]: [Responder] Successful data transmissiont to the client.", get_thread_id_cached());
            }
        } else if (res == 0) [[unlikely]] {
            //requested to write 0 bytes. typically not an error, but log this event
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOGV_NOTICE(logger, "[Thread {}]: [Responder] 0 bytes sent to the client. Either they requested 0 bytes or this could be an internal server error causing no bytes to be sent.", get_thread_id_cached());
            }
        }
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Responder] Checkpoint 2 reached.", get_thread_id_cached());
        }
        if (close(client.destination) < 0) [[unlikely]] {
            if (HDE::server_config.log_level == FULL) {
                LOG_ERROR(logger, "[Thread {}]: [Responder] An error occured while trying to close the connection. The server will force a shut down.", get_thread_id_cached());
            }
            HDE::reportErrorMessage(logger);
            HDE::Server::logClientInfo("Responder", client.msg, logger);
            shutdown(client.destination, SHUT_RDWR);
        }
        if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
            LOG_INFO(logger, "========================= Log Separator =========================");
        }
        else if ((HDE::server_config.log_level == MINIMAL || HDE::server_config.log_level == DECREASED) && !HDE::server_config.disable_logging) {
            LOG_INFO(logger, "A client is processed by the server.");
        }
        if (HDE::server_config.continuous_responses) [[likely]] continue;
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / HDE::server_config.responder_responses_per_second));
            continue;
        }
    }
    LOG_NOTICE(logger, "[Thread {}]: [Responder] Responder loop terminated.", get_thread_id_cached());
    return;
}

void HDE::Server::launch(quill::Logger* logger) {
    //The totalUsedThreads and individual thread allocation for each tasks checks are mostly for future performance improvements such as cpu core pinning.
    //Checking server configurations during start up
    if (HDE::server_config.totalUsedThreads > HDE::NUM_THREADS) [[unlikely]] {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The amount of allocated threads is: {} threads. The amount of available threads: {} threads. Exiting...", get_thread_id_cached(), HDE::server_config.totalUsedThreads, HDE::NUM_THREADS);
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.threadsForAccepter > HDE::NUM_THREADS - 2 || HDE::server_config.threadsForHandler > HDE::NUM_THREADS - 2 || HDE::server_config.threadsForResponder > HDE::NUM_THREADS - 2) [[unlikely]] {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The maximum thread count for any task Accepter, Handler, or Responder is {} threads, thy shall not go over that. Exiting...", get_thread_id_cached(), std::to_string(HDE::NUM_THREADS - 2));
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.threadsForAccepter < 1 || HDE::server_config.threadsForHandler < 1 || HDE::server_config.threadsForResponder < 1) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The minimum value for each tasks must be 1 threads.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.totalUsedThreads < 3) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The minimum value for total used threads is 3. The amount allocated: {}", HDE::get_thread_id_cached(), std::to_string(HDE::server_config.totalUsedThreads));
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.queueCount < 1) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid queueCount configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.MAX_CONNECTIONS_PER_SECOND < 1) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid MAX_CONNECTIONS_PER_SECOND configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.MAX_ADDRESS_QUEUE_SIZE < -1) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid server_config.MAX_ADDRESS_QUEUE_SIZE configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.MAX_RESPONSES_QUEUE_SIZE < -1) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid max_responses_queue_size configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.MAX_BUFFER_SIZE < 1) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid server_config.MAX_BUFFER_SIZE configuration. Normally I'd recommend setting the client request size in bytes to around 30000.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (static_cast<int>(HDE::server_config.log_level) < 0) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid server_config.log_level configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    }
    if (HDE::NUM_THREADS < 1)[[unlikely]] {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] This is not your fault; the server doesn't return a valid thread amount.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } 
    //Warnings/Advisories
    if (!HDE::server_config.disable_warnings){
        if (HDE::server_config.MAX_BUFFER_SIZE < 30000 && HDE::server_config.MAX_BUFFER_SIZE > 500) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [Main Thread] WARNING: BUFFER_SIZE might be insufficient to receive client requests.", HDE::get_thread_id_cached());
        } else if (HDE::server_config.MAX_ADDRESS_QUEUE_SIZE < 10000) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [Main Thread] ADVICE: It is recommended to have server_config.MAX_ADDRESS_QUEUE_SIZE more than 10000, in case the amount of requests backs up during peaj/extreme loads.", HDE::get_thread_id_cached());
        } else if (HDE::server_config.MAX_RESPONSES_QUEUE_SIZE < 10000) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [Main Thread] ADVICE: It is recommended to have max_responses_queue_size more than 10000, in case the amount of responses backs up during peak/extreme loads.", HDE::get_thread_id_cached());
        }
    }
    cache.load_static_files(file_routes_list, logger);
    //Configuring socket options
    int opt = 1;
    setsockopt(get_socket() -> get_sock(), SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(get_socket() -> get_sock(), SOL_SOCKET, SO_RCVBUF, &HDE::server_config.MAX_BUFFER_SIZE, sizeof(HDE::server_config.MAX_BUFFER_SIZE));
    setsockopt(get_socket() -> get_sock(), SOL_SOCKET, SO_SNDBUF, &HDE::server_config.MAX_BUFFER_SIZE, sizeof(HDE::server_config.MAX_BUFFER_SIZE));
    //can totally remove, it's just the upper cap for the variables; they won't even be used anyway, they should be disabled to get max throughput
    if (HDE::server_config.handler_responses_per_second > 1000) [[unlikely]] {
        HDE::server_config.handler_responses_per_second = 1000;
    }
    if (HDE::server_config.responder_responses_per_second > 1000) [[unlikely]] {
        HDE::server_config.responder_responses_per_second = 1000;
    }
    std::ios_base::sync_with_stdio(HDE::server_config.IO_SYNCHONIZATION);
    HDE::AddressQueue address_queue;
    HDE::ResponderQueue responder_queue;
    std::vector<std::jthread> processes(HDE::server_config.totalUsedThreads);
    //initialize the threads
    for (size_t i = 0; i < HDE::server_config.threadsForAccepter; ++i) {
        processes[i] = std::jthread(&HDE::Server::accepter, this, std::ref(address_queue), logger);
    }
    for (size_t i = HDE::server_config.threadsForAccepter; i < HDE::server_config.threadsForAccepter + HDE::server_config.threadsForHandler; ++i) {
        processes[i] = std::jthread(&HDE::Server::handler, this, std::ref(address_queue), std::ref(responder_queue), logger);
    }
    for (size_t i = HDE::server_config.threadsForAccepter + HDE::server_config.threadsForHandler; i < HDE::server_config.totalUsedThreads; ++i) {
        processes[i] = std::jthread(&HDE::Server::responder, this, std::ref(responder_queue), logger);
    }
    LOG_INFO(logger, "[Thread {}]: [Main Thread] Threads initialized.", get_thread_id_cached());
    HDE::serverState.finished_initialization.store(true, std::memory_order_release);
    for (int i = 0; i < processes.size(); ++i) {
        finish_initialization.notify_all();
    }
    LOG_INFO(logger, "[Thread {}]: [Main Thread] Main thread finished executing.", get_thread_id_cached());
}

#ifdef __APPLE__
    //int pin_thread_to_core(int cpu_id) {
        //just keep this empty it's kinda useless but dont delete it
    //}
#elif __linux__
    void pin_thread_to_core(std::thread& t, int core_id) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(core_id, &cpuset);
        
        pthread_t native = t.native_handle();
        pthread_setaffinity_np(native, sizeof(cpu_set_t), &cpuset);
    }
#endif

//side dev notes

/* In launch():
for (size_t i = 0; i < threadsForAccepter; ++i) {
    processes[i] = std::jthread(&Server::accepter, this, std::ref(address_queue));
    pin_thread_to_core(processes[i], i % num_cores);  // Pin to specific core
}

To implement protocol buffers - example
-  Overkill unless cross-language compatibilit (most likely), or high throughput.
Install Protocol Buffers:
brew install protobuf  # macOS
apt install protobuf-compiler  # Linux

# Define schema (request.proto):
syntax = "proto3";

message HttpRequest {
    string method = 1;
    string path = 2;
    map<string, string> headers = 3;
    bytes body = 4;
}

# Generate C++ code:
protoc --cpp_out=. request.proto

# Use in code:
#include "request.pb.h"

HttpRequest req;
req.set_method("GET");
req.set_path("/");

std::string serialized = req.SerializeAsString();  // Fast!
// Send over network...
*/
