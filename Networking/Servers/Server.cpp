

//If code is commented out do not question


//sometimes code calls "call to consteval function ..." as an error but it's just IntelliSense acting up


#define SERVER_CPP_IMPLEMENTATION
#define NS_PRIVATE_IMPLEMENTATION
#define MTL_PRIVATE_IMPLEMENTATION
#define CA_PRIVATE_IMPLEMENTATION
#include "Foundation/Foundation.hpp"
#include "Metal/Metal.hpp"
#include "QuartzCore/QuartzCore.hpp"
#include "Server.hpp"
//dev notes
//Developed for C++23.
/*
Performance optimization goals:
- Protocol Buffers/FlatBuffers: use compact, binary serialization formats; ditch JSON/XML
- If possible, try ditch the standard malloc/new and try custom high-frequency allocations like object pooling or arena allocators
- If possible, try using Profile-Guided Optimization (PGO); compiler looks at performance profile during runtime and perform runtime optimizations to the final binary
(Obscure)
[compiler] -fprofile-generate; ./a.out OR ./main; g++ -fprofile-use
- Configure OS to utilize large memory pages (2MB - 1GB) instead of the standard 4kB
- If possible, try allocating memory on the same physical memory bank attached to the CPU socket that will primarily use the data
- using a dedicated core to spin on a condition instead of using a blocking lock for extremely-low-latency situations
- try batch data together and process them all at once
- pass std::exeution::par as the first parameters of <algorithm> functions, C++17+ only.
- User-Space Networking: expose applications directly to networking cards (bypass kernel) to lower latency

might need to replace std::this_thread::yield() with either arm64_atomics::cpu_yield() or __builtin_arm_yield();
*/

///only use PGO near the end of production/near feature-complete

//0x80000000 = 2147483648 -> -2147483647 (overflow)
//0x8000000000000000 = 9223372036854775808 -> -9223372036854775807 (overflow)

//in the future, if possible create a struct for each of these mutexes/conditional variables and add padding; but only do it for frequently-accessed ones.
alignas(CACHE_LINE_SIZE) socklen_t addrlen = sizeof(struct sockaddr_in);

//definitions
//keep conditional variables separate; they might cause unexpected deadlocks
alignas(CACHE_LINE_SIZE) std::condition_variable finish_initialization;
alignas(CACHE_LINE_SIZE) std::condition_variable addr_in_addr_queue;
alignas(CACHE_LINE_SIZE) std::condition_variable resp_in_res_queue;

//preload error code pages
std::string bad_request_response, unauthorized_response, forbidden_response, not_found_response, method_not_allowed_response;

//for future attempts:     [Thread <thread id>]: [<processing component, if possible>] [<message>]

//Main code, do not modify

HDE::Server::Server(quill::Logger* logger) : SimpleServer(AF_INET, SOCK_STREAM, 0, HDE::server_config.PORT, INADDR_ANY, HDE::server_config.queueCount) {
    HDE::Server::launch(logger);
}

//custom ARM64 assembly instructions
//try to see if you can specify what registers you will be using in the clobber list
//asm volatile(<asm in string> : <input> : <output> : <clobber-list>);
namespace arm64_atomics {
    inline uint64_t fetch_add_explicit_llsc(uint64_t* ptr, uint64_t val) {
        uint64_t result, tmp;
        uint32_t status;
        asm volatile(
            "1: ldaxr %[result], [%[ptr]]\n"
            "add %[tmp], %[result], %[val]\n"
            "stlxr %w[status], %[tmp], [%[ptr]]\n"
            "cbnz %w[status], 1b\n"
            : [result] "=&r" (result), [tmp] "=&r" (tmp), [status] "=&r" (status)
            : [ptr] "r" (ptr), [val] "r" (val)
            : "memory", "cc"
        );
        return result;
    }
    inline uint64_t load_acquire(const uint64_t* ptr) {
        uint64_t result;
        asm volatile(
            "ldar %[result], [%[ptr]]"
            : [result] "=r" (result)
            : [ptr] "r" (ptr)
            : "memory"
        );
        return result;
    }
    inline void store_release(uint64_t* ptr, uint64_t val) {
        asm volatile(
            "stlr %[val], [%[ptr]]"
            :
            : [ptr] "r" (ptr), [val] "r" (val)
            : "memory"
        );
    }
    inline uint64_t load_relaxed(const uint64_t* ptr) {
        uint64_t result;
        asm volatile(
            "ldr %[result], [%[ptr]]"
            : [result] "=r" (result)
            : [ptr] "r" (ptr)
            :
        );
        return result;
    }
    inline void store_relaxed(uint64_t* ptr, uint64_t val) {
        asm volatile(
            "str %[val], [%[ptr]]"
            :
            : [ptr] "r" (ptr), [val] "r" (val)
            :
        );
    }
    inline bool compare_exchange_weak_acquire(uint64_t* ptr, uint64_t* expected, uint64_t desired) {
        uint64_t old_val;
        uint32_t status;
        asm volatile(
            "ldaxr %[old], [%[ptr]]\n"
            "cmp %[old], %[exp]\n"
            "b.ne 2f\n"
            "stxr %w[status], %[_new], [%[ptr]]\n"
            "b 3f\n"
            "clrex\n"
            "mov %w[status], #1\n"
            : [old] "=&r" (old_val), [status] "=&r" (status)
            : [ptr] "r" (ptr), [exp] "r" (*expected), [_new] "r" (desired)
            : "memory", "cc"
        );
        *expected = old_val;
        return status == 0;
    }
    //read prefetch
    inline void prefetch_read(const void* addr) {
        asm volatile(
            "prfm pldl1keep, [%[addr]]" //L1
            :
            : [addr] "r" (addr)
            :
        );
    }
    //write prefetch
    inline void prefetch_write(const void* addr) {
        asm volatile(
            "prfm pstl1keep, [%[addr]]" //L1
            :
            : [addr] "r" (addr)
            :
        );
    }
    //prefetch streaming, low temporal locality, use only once
    inline void prefetch_stream_read(const void* addr) {
        asm volatile(
            "prfm pldl1strm, [%[addr]]" //streaming hint
            :
            : [addr] "r" (addr)
            :
        );
    }
    //yield hint in asm instructions
    inline void cpu_yield() {
        asm volatile("yield" ::: "memory");
    }
    //yield hint but using built-in function
    inline void arm_yield() {
        __builtin_arm_yield();
    }
    //issue instruction synchronization barrier, ensures all previous instructions complete before continuing
    inline void isb() {
        asm volatile("isb" ::: "memory");
    }
    //data memory barrier - all memory accesses complete
    inline void dmb() {
        asm volatile("dmb ish" ::: "memory");  //inner shareable
    }
    //data memory barrier - only stores
    inline void dmb_st() {
        asm volatile("dmb ishst" ::: "memory");
    }
    // Data memory barrier - only loads
    inline void dmb_ld() {
        asm volatile("dmb ishld" ::: "memory");
    }
};

//Utilities
inline std::string_view HDE::get_thread_id_cached() {
    thread_local std::string cached_id = []() {
        std::ostringstream oss;
        oss << std::this_thread::get_id();
        return oss.str();
    }();
    return cached_id;
}
//Thread safe
inline void HDE::Server::logClientInfo(const std::string_view processing_component, const std::string_view message, quill::Logger* logger) const {
    if (!message.empty() && HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) [[likely]] {
        LOG_INFO(logger, "[Thread {}]: logClientInfo(): {}", HDE::get_thread_id_cached(), processing_component, message);
    } else if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) [[unlikely]] {
        LOG_INFO(logger, "[Thread {}]: logClientInfo(): <empty>", HDE::get_thread_id_cached(), processing_component);
    } else {
        return;
    }
}
//Thread-safe, only prints if static_cast<int>(HDE::log_level) is set to anything higher than 0.
inline void HDE::reportErrorMessage(quill::Logger* logger) {
    int error_code = errno;
    if (HDE::server_config.log_level != MINIMAL) {
        LOG_ERROR(logger, "[Thread {}]: An error has occured (Description, if any, line above).", HDE::get_thread_id_cached());
    }
    if (errno == EINTR) [[unlikely]] {
        if (HDE::server_config.log_level != MINIMAL) LOG_ERROR(logger, "[Thread {}]: Message: A possible interrupted system call is detected.", HDE::get_thread_id_cached());
    } else if (errno == EMFILE || errno == ENFILE) [[unlikely]] {
        if (HDE::server_config.log_level != MINIMAL) LOG_ERROR(logger, "[Thread {}]: Message: The server is using a lot of resources (Too many open files). Check immediately.", HDE::get_thread_id_cached());
    } else if (HDE::server_config.log_level != MINIMAL) [[likely]] {
        LOG_ERROR(logger, "[Thread {}]: Message: {}", HDE::get_thread_id_cached(), strerror(errno));
    } else return;
}
//probably not ever gonna use this function but don't delete it we might, and i say might need it in the future (no promises)
inline void HDE::clean_server_shutdown(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue) {
    HDE::serverState.stop_server.store(true, std::memory_order_seq_cst);
    resp_in_res_queue.notify_all();
    addr_in_addr_queue.notify_all();
}
//Thread-safe
//I actually have no idea how this works
inline bool HDE::is_rate_limited(std::string_view client_ip) {
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
    //have some code here that will process the query string if necessary i.e. "http://a.com/a/b?a=a&b=b&c=c"
    //HDE::HTTPParser::parse_query_string(request);
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

//query_string has to start with ?
//input example: "?a=a&b=b&c=c&d=d"
inline void HDE::HTTPParser::parse_query_string(std::string_view query_string, ParsedRequest& request) {
    //parse the query string then put in ParsedRequest.query_str_parsed. do some error checking first
    //validating query string
    if (!HDE::HTTPValidator::is_valid_query_string(query_string)) return;
    if (query_string.contains('&')) {
        __builtin_prefetch(&query_string, 0, 3);
        __builtin_prefetch(&request, 1, 3);
        request.query_str_parsed.push_back({std::move(HDE::HTTPParser::parse_url_encoding(static_cast<std::string>(query_string.substr(1, static_cast<int>(query_string.find('=') - 1))))), std::move(HDE::HTTPParser::parse_url_encoding(static_cast<std::string>(query_string.substr(query_string.find('=') + 1, static_cast<int>(query_string.length() - query_string.find('='))))))});
    } else {
        size_t arg_size;
        __builtin_prefetch(&query_string, 0, 3);
        __builtin_prefetch(&request, 1, 3);
        for (int i = 0; i < query_string.length(); i += arg_size) {
            request.query_str_parsed.push_back({std::move(HDE::HTTPParser::parse_url_encoding(static_cast<std::string>(query_string.substr(i + 1, static_cast<int>(query_string.find('=', i)) - (i))))), std::move(HDE::HTTPParser::parse_url_encoding(static_cast<std::string>(query_string.substr(query_string.find('=', i) + 1, static_cast<int>(query_string.find('&', i) - query_string.find('=', i)) - 1))))});
            arg_size = query_string.find('&', i) - i;
        }
    }
}

//charset UTF-8
std::string_view HDE::HTTPParser::parse_url_encoding(const std::string& input) {
    if (!input.contains("%")) return input;
    std::stringstream ss;
    for (size_t i = 0; i < input.length(); ++i) {
        if (input[i] == '%') {
            if (i + 2 < input.length()) { // Ensure there are two hex digits
                std::string hex_code = input.substr(i + 1, 2);
                try {
                    int char_code = std::stoi(hex_code, nullptr, 16);
                    ss << static_cast<char>(char_code);
                    i += 2;
                } catch (const std::invalid_argument& e) {
                    ss << '%';
                } catch (const std::out_of_range& e) {
                    ss << '%';
                }
            } else {
                ss << '%'; // Malformed encoding, append '%' as literal
            }
        } else if (input[i] == '+') {
            ss << ' '; // Convert '+' back to space
        } else {
            ss << input[i]; // Append other characters directly
        }
    }
    return ss.str();
}

inline std::optional<std::string> HDE::ResponseCache::load_file_response(const std::string& file_path, const bool include_header) const {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) [[unlikely]] throw std::runtime_error(std::format("File isn't open for {} brodie", file_path));
    auto size = file.tellg();
    if (size <= 0) [[unlikely]] {
        file.close();
        throw std::runtime_error(std::format("Read position for {} is invalid brodie", file_path));
    }
    file.seekg(0);
    std::string content;
    content.resize(size);
    file.read(content.data(), size);
    /*if (file_path == "/Users/trangtran/Desktop/coding_files/a/Networking/Servers/html/http_err/err_400.html") {
        file.read(content.data(), size);
    } else {
        file.read(content.data(), size);
    }*/
    file.close();
    std::string_view content_type = HDE::ResponseCache::get_content_type(file_path);
    if (include_header) return std::format(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"           // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                     // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"           // XSS protection
        "\r\n{}",
        content_type, static_cast<long long>(size), content
    );
    else return content;
}

inline std::string HDE::ResponseCache::read_file_getline(const std::string& file_path, const bool add_newline_char) const {
    std::ifstream file(file_path);
    std::string res, line;
    while (std::getline(file, line)) {
        res += (line + (add_newline_char ? "\n" : ""));
    }
    file.close();
    if (res.empty()) throw std::runtime_error(std::format("File {} might be empty or an error occured. Fuck you", file_path));
    return res;
}

inline void HDE::ResponseCache::load_static_files(const std::vector<std::pair<std::string, std::string>>& routes, quill::Logger* logger) {
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
    loaded_routes = routes;
    for (const auto& [url_path, file_path] : routes) {
        auto response_opt = load_file_response(file_path, true); 
        if (!response_opt.has_value()) [[unlikely]] {
            LOG_ERROR(logger, "WARNING: Cannot load file: {} for URL: {}", file_path, url_path);
            continue;
        }
        cache[url_path] = std::move(response_opt.value());
        LOG_INFO(logger, "[{:>8} bytes] Mapped {:>25} -> {}", cache[url_path].length(), url_path, file_path);
    }
    std::string temp_str = "";
    std::optional<std::string> temp = HDE::cache.read_file_getline("/Users/trangtran/Desktop/coding_files/a/Networking/Servers/html/http_err/err_400.html", false);
    if (temp.has_value()) temp_str = temp.value();
    else throw std::runtime_error("Error 400 page aren't loaded correctly. Fuck you");
    bad_request_response = std::format(
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n{}", temp_str.length(), temp_str
    );
    temp = HDE::cache.read_file_getline("/Users/trangtran/Desktop/coding_files/a/Networking/Servers/html/http_err/err_401.html", false);
    if (temp.has_value()) temp_str = temp.value();
    else throw std::runtime_error("Error 401 page aren't loaded correctly. Fuck you");
    unauthorized_response = std::format(
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: Basic\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n{}", temp_str.length(), temp_str
    );
    temp = HDE::cache.read_file_getline("/Users/trangtran/Desktop/coding_files/a/Networking/Servers/html/http_err/err_403.html", false);
    if (temp.has_value()) temp_str = temp.value();
    else throw std::runtime_error("Error 403 page aren't loaded correctly. Fuck you");
    forbidden_response = std::format(
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n{}", temp_str.length(), temp_str
    );
    temp = HDE::cache.read_file_getline("/Users/trangtran/Desktop/coding_files/a/Networking/Servers/html/http_err/err_404.html", false);
    if (temp.has_value()) temp_str = temp.value();
    else throw std::runtime_error("Error 404 page aren't loaded correctly. Fuck you");
    not_found_response = std::format(
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n{}", temp_str.length(), temp_str
    );
    temp = HDE::cache.read_file_getline("/Users/trangtran/Desktop/coding_files/a/Networking/Servers/html/http_err/err_405.html", false);
    if (temp.has_value()) temp_str = temp.value();
    else throw std::runtime_error("Error 405 page aren't loaded correctly. Fuck you");
    method_not_allowed_response = std::format(
        "HTTP/1.1 405 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "Allow: GET, POST, PUT, HEAD\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
        "\r\n{}", temp_str.length(), temp_str
    );
    LOG_DEBUG(logger, "[400]: {}", bad_request_response);
    LOG_DEBUG(logger, "[401]: {}", unauthorized_response);
    LOG_DEBUG(logger, "[403]: {}", forbidden_response);
    LOG_DEBUG(logger, "[404]: {}", not_found_response);
    LOG_DEBUG(logger, "[405]: {}", method_not_allowed_response);
    LOG_INFO(logger, "Loaded {} custom routes", cache.size());
}

//automatically returns not_found_response so no need to worry
inline std::string_view HDE::ResponseCache::get_response(std::string_view path) const noexcept {
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
    auto it = cache.find(std::string(path));
    if (it != cache.end()) [[likely]] return it -> second; //try exact path match first
    __builtin_prefetch(&path, 0, 3);
    if (path == "/") [[unlikely]] { //if path is "/", try "/index.html"
        __builtin_prefetch(&cache, 0, 3);
        it = cache.find("/index.html");
        if (it != cache.end()) return it -> second;
    }
    __builtin_prefetch(&path, 0, 3);
    if (path.size() > 1 && path.back() == '/') [[unlikely]] { //if path is directory (ends with /), try appending "index.html"
        std::string index_path = std::string(path) + "index.html";
        __builtin_prefetch(&cache, 0, 3);
        it = cache.find(index_path);
        if (it != cache.end()) return it -> second;
    }
    return not_found_response; //404
}
//try to not use this function it is broken
inline bool HDE::ResponseCache::reload_file(const std::string& path, const std::string& file_path, quill::Logger* logger) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) [[unlikely]] return false;
    auto size = file.tellg();
    if (size <= 0) [[unlikely]] {
        file.close();
        return false;
    }
    file.seekg(0);
    std::string content;
    content.resize(size);
    file.read(content.data(), size);
    file.close();
    std::string_view content_type = HDE::ResponseCache::get_content_type(file_path);
    std::string&& response = std::format(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "\r\n{}",
        content_type, static_cast<long long>(size), content
    );
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
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

//do not use
inline size_t HDE::ResponseCache::reload_all_files(quill::Logger* logger) {
    size_t count = 0;
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
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
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
    cache.clear();
}

inline size_t HDE::ResponseCache::get_cache_size() const {
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
    return cache.size();
}

// Add these implementations to Server.cpp

inline void HDE::ServerMetrics::record_request(bool success, size_t bytes_in, size_t bytes_out) {
    total_requests.fetch_add(1, std::memory_order_relaxed);
    if (success) {
        successful_requests.fetch_add(1, std::memory_order_relaxed);
    } else {
        failed_requests.fetch_add(1, std::memory_order_relaxed);
    }
    bytes_received.fetch_add(bytes_in, std::memory_order_relaxed);
    bytes_sent.fetch_add(bytes_out, std::memory_order_relaxed);
    auto now = std::chrono::steady_clock::now();
    size_t window_idx = current_window.load(std::memory_order_relaxed);
    auto& window = request_windows[window_idx];
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - window.timestamp).count();
    if (elapsed >= 1) {
        size_t next_idx = (window_idx + 1) % WINDOW_SIZE;
        request_windows[next_idx].count.store(1, std::memory_order_relaxed);
        request_windows[next_idx].timestamp = now;
        current_window.store(next_idx, std::memory_order_release);
    } else {
        window.count.fetch_add(1, std::memory_order_relaxed);
    }
}

inline double HDE::ServerMetrics::get_instantaneous_rps() const {
    auto now = std::chrono::steady_clock::now();
    uint64_t total_count = 0;
    int valid_windows = 0;
    for (const auto& window : request_windows) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - window.timestamp).count();
        if (age < HDE::server_config.time_window_for_rps) {
            total_count += window.count.load(std::memory_order_relaxed);
            valid_windows++;
        }
    }
    return valid_windows > 0 ? static_cast<double>(total_count) / valid_windows : 0.0;
}

inline uint64_t HDE::ServerMetrics::get_total_memory() const {
#ifdef __APPLE__
    int mib[2] = {CTL_HW, HW_MEMSIZE};
    uint64_t total_mem = 0;
    size_t len = sizeof(total_mem);
    sysctl(mib, 2, &total_mem, &len, nullptr, 0);
    return total_mem;
#elif __linux__
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    while (std::getline(meminfo, line)) {
        if (line.starts_with("MemTotal:")) {
            std::istringstream iss(line);
            std::string label;
            uint64_t value;
            iss >> label >> value;
            return value * 1024; // Convert KB to bytes
        }
    }
#endif
    return 0;
}

inline void HDE::ServerMetrics::get_memory_usage(uint64_t& used_bytes, double& percent) const {
#ifdef __APPLE__
    mach_port_t host_port = mach_host_self();
    vm_size_t page_size;
    vm_statistics64_data_t vm_stats;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    host_page_size(host_port, &page_size);
    host_statistics64(host_port, HOST_VM_INFO64, (host_info64_t)&vm_stats, &count);
    // Calculate actual used memory (active + wired)
    // Active: currently in use
    // Wired: cannot be paged out (kernel, etc)
    uint64_t active_mem = vm_stats.active_count * page_size;
    uint64_t wired_mem = vm_stats.wire_count * page_size;
    uint64_t compressed_mem = vm_stats.compressor_page_count * page_size;
    used_bytes = active_mem + wired_mem + compressed_mem;
    uint64_t total_mem = get_total_memory();
    percent = total_mem > 0 ? (static_cast<double>(used_bytes) / total_mem) * 100.0 : 0.0;
#elif __linux__
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    uint64_t total = 0, available = 0;
    
    while (std::getline(meminfo, line)) {
        std::istringstream iss(line);
        std::string label;
        uint64_t value;
        
        if (line.starts_with("MemTotal:")) {
            iss >> label >> value;
            total = value * 1024;
        } else if (line.starts_with("MemAvailable:")) {
            iss >> label >> value;
            available = value * 1024;
        }
    }
    
    used_bytes = total - available;
    percent = total > 0 ? (static_cast<double>(used_bytes) / total) * 100.0 : 0.0;
#else
    used_bytes = 0;
    percent = 0.0;
#endif
}

inline HDE::ServerMetrics::MemoryBreakdown HDE::ServerMetrics::get_memory_breakdown() const {
    MemoryBreakdown breakdown = {0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0};
#ifdef __APPLE__
    mach_port_t host_port = mach_host_self();
    vm_size_t page_size;
    vm_statistics64_data_t vm_stats;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    host_page_size(host_port, &page_size);
    host_statistics64(host_port, HOST_VM_INFO64, (host_info64_t)&vm_stats, &count);
    // Use actual system total memory, not calculated from vm_stats
    uint64_t total = get_total_memory();
    if (total > 0) {
        breakdown.active_percent = (vm_stats.active_count * page_size * 100.0) / total;
        breakdown.wired_percent = (vm_stats.wire_count * page_size * 100.0) / total;
        breakdown.compressed_percent = (vm_stats.compressor_page_count * page_size * 100.0) / total;
        breakdown.free_percent = ((vm_stats.free_count + vm_stats.inactive_count + vm_stats.speculative_count + vm_stats.purgeable_count) * page_size * 100.0) / total;
    }
#elif __linux__
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    uint64_t total = 0, available = 0, buffers = 0, cached = 0;
    
    while (std::getline(meminfo, line)) {
        std::istringstream iss(line);
        std::string label;
        uint64_t value;
        
        if (line.starts_with("MemTotal:")) {
            iss >> label >> value;
            total = value * 1024;
        } else if (line.starts_with("MemAvailable:")) {
            iss >> label >> value;
            available = value * 1024;
        } else if (line.starts_with("Buffers:")) {
            iss >> label >> value;
            buffers = value * 1024;
        } else if (line.starts_with("Cached:")) {
            iss >> label >> value;
            cached = value * 1024;
        }
    }
    
    breakdown.active = total - available - buffers - cached;
    breakdown.wired = buffers; // Approximate
    breakdown.compressed = 0; // Linux doesn't expose this easily
    breakdown.free = available;
    
    if (total > 0) {
        breakdown.active_percent = (breakdown.active * 100.0) / total;
        breakdown.wired_percent = (breakdown.wired * 100.0) / total;
        breakdown.compressed_percent = 0.0;
        breakdown.free_percent = (breakdown.free * 100.0) / total;
    }
#endif
    return breakdown;
}

inline int HDE::ServerMetrics::get_memory_pressure() const {
#ifdef __APPLE__
    // macOS memory pressure levels
    // 1 = Normal (green)
    // 2 = Warning (yellow) 
    // 4 = Critical (red)
    mach_port_t host_port = mach_host_self();
    vm_statistics64_data_t vm_stats;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(host_port, HOST_VM_INFO64, (host_info64_t)&vm_stats, &count) != KERN_SUCCESS) return 1; //Default to normal if can't read
    vm_size_t page_size;
    host_page_size(host_port, &page_size);
    // Calculate memory pressure indicators
    uint64_t free_pages = vm_stats.free_count;
    uint64_t inactive_pages = vm_stats.inactive_count;
    uint64_t active_pages = vm_stats.active_count;
    uint64_t speculative_pages = vm_stats.speculative_count;
    uint64_t wired_pages = vm_stats.wire_count;
    uint64_t compressed_pages = vm_stats.compressor_page_count;
    uint64_t purgeable_pages = vm_stats.purgeable_count;
    // Total available = free + inactive + purgeable + speculative
    uint64_t available_pages = free_pages + inactive_pages + purgeable_pages + speculative_pages;
    uint64_t total_pages = available_pages + active_pages + wired_pages;
    // Check page-outs (memory being written to swap)
    uint64_t pageouts = vm_stats.pageouts;
    // Calculate available memory ratio
    double available_ratio = total_pages > 0 ? static_cast<double>(available_pages) / total_pages : 0.0;
    // macOS considers memory pressure based on:
    // 1. Available memory ratio
    // 2. Swap activity (pageouts)
    // 3. Compression ratio
    if (available_ratio < 0.05 || pageouts > 1000) return 4; //critical
    else if (available_ratio < 0.15 || pageouts > 100) return 2; //warning
    else return 1; //normal
#elif __linux__
    // Linux doesn't have native "memory pressure" but we can approximate
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    uint64_t total = 0, available = 0, swap_total = 0, swap_free = 0;
    
    while (std::getline(meminfo, line)) {
        std::istringstream iss(line);
        std::string label;
        uint64_t value;
        
        if (line.starts_with("MemTotal:")) {
            iss >> label >> value;
            total = value;
        } else if (line.starts_with("MemAvailable:")) {
            iss >> label >> value;
            available = value;
        } else if (line.starts_with("SwapTotal:")) {
            iss >> label >> value;
            swap_total = value;
        } else if (line.starts_with("SwapFree:")) {
            iss >> label >> value;
            swap_free = value;
        }
    }
    
    double available_ratio = total > 0 ? static_cast<double>(available) / total : 0.0;
    double swap_used_ratio = swap_total > 0 ? 
        static_cast<double>(swap_total - swap_free) / swap_total : 0.0;
    
    // Linux thresholds - adjusted for high-performance servers
    // Critical: Extremely low available memory AND heavy swap usage
    if (available_ratio < 0.03 && swap_used_ratio > 0.7) {
        return 4; // CRITICAL
    }
    // Warning: Low available memory OR significant swap usage
    else if (available_ratio < 0.10 || swap_used_ratio > 0.4) {
        return 2; // WARNING
    }
    else {
        return 1; // NORMAL
    }
#else
    return 1; // Default to normal
#endif
}

inline HDE::ServerMetrics::CPUBreakdown HDE::ServerMetrics::get_cpu_breakdown() const {
    std::scoped_lock<std::mutex> lock(metrics_mutex);
    HDE::ServerMetrics::CPUBreakdown breakdown = {0.0, 0.0, 0.0, 0.0};
#ifdef __APPLE__
    host_cpu_load_info_data_t cpu_info;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info64_t)&cpu_info, &count) != KERN_SUCCESS) return breakdown;
    uint64_t user = cpu_info.cpu_ticks[CPU_STATE_USER] + cpu_info.cpu_ticks[CPU_STATE_NICE];
    uint64_t system = cpu_info.cpu_ticks[CPU_STATE_SYSTEM];
    uint64_t idle = cpu_info.cpu_ticks[CPU_STATE_IDLE];
    uint64_t total = user + system + idle;
    // On first measurement, just store values
    if (first_measurement) {
        prev_cpu_user = user;
        prev_cpu_system = system;
        prev_cpu_idle = idle;
        prev_cpu_total = total;
        first_measurement = false;
        return breakdown;
    }
    uint64_t user_diff = user - prev_cpu_user;
    uint64_t system_diff = system - prev_cpu_system;
    uint64_t idle_diff = idle - prev_cpu_idle;
    uint64_t total_diff = total - prev_cpu_total;
    prev_cpu_user = user;
    prev_cpu_system = system;
    prev_cpu_idle = idle;
    prev_cpu_total = total;
    if (total_diff == 0) return breakdown;
    breakdown.user = (user_diff * 100.0) / total_diff;
    breakdown.system = (system_diff * 100.0) / total_diff;
    breakdown.idle = (idle_diff * 100.0) / total_diff;
    breakdown.total_used = breakdown.user + breakdown.system;
#elif __linux__
    std::ifstream stat("/proc/stat");
    std::string line;
    std::getline(stat, line);
    
    std::istringstream iss(line);
    std::string cpu;
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
    iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
    
    uint64_t user_total = user + nice;
    uint64_t system_total = system + irq + softirq;
    uint64_t idle_total = idle + iowait;
    uint64_t total = user_total + system_total + idle_total + steal;
    
    if (first_measurement) {
        prev_cpu_user = user_total;
        prev_cpu_system = system_total;
        prev_cpu_idle = idle_total;
        prev_cpu_total = total;
        return breakdown;
    }
    
    uint64_t user_diff = user_total - prev_cpu_user;
    uint64_t system_diff = system_total - prev_cpu_system;
    uint64_t idle_diff = idle_total - prev_cpu_idle;
    uint64_t total_diff = total - prev_cpu_total;
    
    prev_cpu_user = user_total;
    prev_cpu_system = system_total;
    prev_cpu_idle = idle_total;
    prev_cpu_total = total;
    
    if (total_diff == 0) return breakdown;
    
    breakdown.user = (user_diff * 100.0) / total_diff;
    breakdown.system = (system_diff * 100.0) / total_diff;
    breakdown.idle = (idle_diff * 100.0) / total_diff;
    breakdown.total_used = breakdown.user + breakdown.system;
#endif
    
    return breakdown;
}

inline double HDE::ServerMetrics::get_cpu_usage() const {
    CPUBreakdown breakdown = get_cpu_breakdown();
    return breakdown.total_used;
}

inline std::string HDE::ServerMetrics::get_metrics_json() const {
    auto uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time).count();
    uint64_t total = total_requests.load(std::memory_order_relaxed);
    uint64_t success = successful_requests.load(std::memory_order_relaxed);
    uint64_t failed = failed_requests.load(std::memory_order_relaxed);
    uint64_t bytes_in = bytes_received.load(std::memory_order_relaxed);
    uint64_t bytes_out = bytes_sent.load(std::memory_order_relaxed);
    double avg_rps = uptime_seconds > 0 ? static_cast<double>(total) / uptime_seconds : 0.0;
    double instant_rps = get_instantaneous_rps();
    CPUBreakdown cpu = get_cpu_breakdown();
    uint64_t mem_used = 0;
    double mem_percent = 0.0;
    get_memory_usage(mem_used, mem_percent);
    uint64_t total_mem = get_total_memory();
    int mem_pressure = get_memory_pressure();
    MemoryBreakdown mem = get_memory_breakdown();
    return std::format(
        "{{\n"
        "  \"uptime_seconds\": {},\n"
        "  \"total_requests\": {},\n"
        "  \"successful_requests\": {},\n"
        "  \"failed_requests\": {},\n"
        "  \"bytes_received\": {},\n"
        "  \"bytes_sent\": {},\n"
        "  \"requests_per_second\": {:.2f},\n"
        "  \"instantaneous_rps\": {:.2f},\n"
        "  \"cpu_usage_percent\": {:.1f},\n"
        "  \"cpu_user_percent\": {:.1f},\n"
        "  \"cpu_system_percent\": {:.1f},\n"
        "  \"cpu_idle_percent\": {:.1f},\n"
        "  \"memory_used_bytes\": {},\n"
        "  \"memory_percent\": {:.1f},\n"
        "  \"memory_total_bytes\": {},\n"
        "  \"memory_pressure\": {},\n"
        "  \"memory_active_bytes\": {},\n"
        "  \"memory_wired_bytes\": {},\n"
        "  \"memory_compressed_bytes\": {},\n"
        "  \"memory_free_bytes\": {},\n"
        "  \"memory_active_percent\": {:.1f},\n"
        "  \"memory_wired_percent\": {:.1f},\n"
        "  \"memory_compressed_percent\": {:.1f},\n"
        "  \"memory_free_percent\": {:.1f},\n"
        "  \"cache_size\": {},\n"
        "  \"thread_count\": {}\n"
        "}}",
        uptime_seconds, total, success, failed, bytes_in, bytes_out, 
        avg_rps, instant_rps, 
        cpu.total_used, cpu.user, cpu.system, cpu.idle,
        mem_used, mem_percent, total_mem, mem_pressure,
        mem.active, mem.wired, mem.compressed, mem.free,
        mem.active_percent, mem.wired_percent, mem.compressed_percent, mem.free_percent,
        0, HDE::server_config.totalUsedThreads
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

//path has to start with "/"
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
    return method == "GET" || method == "HEAD" || method == "PUT" || method == "POST"; //future: || method == "DELETE"
}

inline bool HDE::HTTPValidator::is_valid_version(std::string_view version) noexcept {
    return version == "HTTP/1.1" || version == "HTTP/1.0"; //future: || vversion == "HTTP/2.0"
}

inline bool HDE::HTTPValidator::is_valid_request_line(std::string_view request) noexcept {
    if (request.find("\r\n") == std::string_view::npos) [[unlikely]] return false;
    if (request.find('\0') != std::string_view::npos) [[unlikely]] return false;
    size_t first_line_end = request.find("\r\n");
    size_t headers_end = request.find("\r\n\r\n");
    // If there's content after headers without Content-Length, suspicious
    if (headers_end != std::string_view::npos) [[unlikely]] {
        std::string_view after_headers = request.substr(headers_end + 4);
        if (!after_headers.empty() && request.find("Content-Length:") == std::string_view::npos) [[unlikely]] return false;
    }
    return true;
}

inline bool HDE::HTTPValidator::is_valid_size(size_t size) noexcept {
    return size >= 0 && size <= 65536; //can increase more
}

inline bool HDE::HTTPValidator::is_valid_query_string(std::string_view query_string) noexcept {
    if (!query_string.starts_with('?')) [[unlikely]] return false;
    if (!query_string.contains('=')) [[unlikely]] return false;
    if (query_string.contains(' ')) [[unlikely]] return false;
    if (query_string.contains('/')) [[unlikely]] return false;
    if (query_string.contains('#')) [[unlikely]] return false;
    if (query_string.contains('$')) [[unlikely]] return false;
    return query_string.starts_with('?') && query_string.contains('=') && !query_string.contains(' ') && query_string.contains('/') && query_string.contains('#') && query_string.contains('$');
}

namespace HDE {
//in the future try to upgrade to modern Metal 4 practices
//also add telemetry/hardware stats to server control panel
//add more request parsing in the gpu
class M2GPUHTTPParser {
private:
    MTL::Device* device;
    MTL::CommandQueue* command_queue;
    MTL::ComputePipelineState* parse_pipeline;
    MTL::ComputePipelineState* validate_pipeline;
    static constexpr size_t RING_SIZE = HDE::server_config.ring_size;
    struct BufferRing {
        MTL::Buffer* request_buffers[RING_SIZE];     // input: HTTP request text
        MTL::Buffer* parsed_buffers[RING_SIZE];      // output: parsed data
        MTL::Buffer* validation_buffers[RING_SIZE];  // output: validation flags
        std::atomic<size_t> current_index{0};        // current buffer slot
    };
    BufferRing buffers;
    size_t max_request_size;   // defaults to MAX_BUFFER_SIZE in constructor
    size_t batch_size;         // defaults to batch_size in constructor
    NS::Error* error;
    quill::Logger* logger;
    void compile_shaders() {
        std::ifstream shader_file("http_parser.metal");
        if (!shader_file.is_open()) [[unlikely]] throw std::runtime_error("Cannot open http_parser.metal. Make sure the file exists in the current directory.");
        std::string shader_source((std::istreambuf_iterator<char>(shader_file)), std::istreambuf_iterator<char>());
        shader_file.close();
        if (shader_source.empty()) [[unlikely]] throw std::runtime_error("http_parser.metal is empty");
        LOG_INFO(logger, "Loaded shader source ({} bytes)", shader_source.size());
        NS::String* source_str = NS::String::string(shader_source.c_str(), NS::UTF8StringEncoding);
        MTL::CompileOptions* options = MTL::CompileOptions::alloc() -> init();
        //options -> setFastMathEnabled(HDE::server_config.fast_floating_point); <- deprecated
        options -> setLanguageVersion(MTL::LanguageVersion2_4); //using Metal 2.4
        //options -> setLanguageVersion(MTL::LanguageVersion4_0);
        if (HDE::server_config.math_mode == 0) { //setting math mode
            options -> setMathMode(MTL::MathModeFast);
        } else if (HDE::server_config.math_mode == 2) {
            options -> setMathMode(MTL::MathModeSafe);
        } else {
            options -> setMathMode(MTL::MathModeRelaxed);
        }
        options -> setEnableLogging(HDE::server_config.allow_gpu_logging);
        options -> setOptimizationLevel(HDE::server_config.optimize_for_bin_size ? MTL::LibraryOptimizationLevelSize : MTL::LibraryOptimizationLevelDefault); //setting global optimization level for metal compiler
        MTL::Library* library = device -> newLibrary(source_str, options, &error);
        options -> release();  // Clean up compile options
        if (!library) [[unlikely]] {
            std::string&& error_msg = error ? std::string(error -> localizedDescription() -> utf8String()) : "Unknown compilation error";
            throw std::runtime_error("Metal shader compilation failed:\n" + error_msg);
        }
        LOG_INFO(logger, "Shader library compiled");
        NS::String* parse_name = NS::String::string("parse_http_requests", NS::UTF8StringEncoding);
        NS::String* validate_name = NS::String::string("validate_urls", NS::UTF8StringEncoding);
        MTL::Function* parse_func = library -> newFunction(parse_name);
        MTL::Function* validate_func = library -> newFunction(validate_name);
        if (!parse_func) [[unlikely]] {
            library -> release();
            throw std::runtime_error("Cannot find 'parse_http_requests' kernel in shader. Check http_parser.metal for correct function name.");
        }
        if (!validate_func) [[unlikely]] {
            library -> release();
            parse_func -> release();
            throw std::runtime_error("Cannot find 'validate_urls' kernel in shader. Check http_parser.metal for correct function name.");
        }
        LOG_INFO(logger, "Found kernel functions: parse_http_requests, validate_urls");
        // pipeline state = optimized, ready-to-execute GPU code
        parse_pipeline = device -> newComputePipelineState(parse_func, &error);
        if (!parse_pipeline) [[unlikely]] {
            std::string&& error_msg = error ? std::string(error -> localizedDescription() -> utf8String()) : "Unknown error";
            validate_func -> release();
            parse_func -> release();
            library -> release();
            throw std::runtime_error("Failed to create parse pipeline:\n" + error_msg);
        }
        validate_pipeline = device -> newComputePipelineState(validate_func, &error);
        if (!validate_pipeline) [[unlikely]] {
            std::string&& error_msg = error ? std::string(error -> localizedDescription() -> utf8String()) : "Unknown error";
            parse_pipeline -> release();
            validate_func -> release();
            parse_func -> release();
            library -> release();
            throw std::runtime_error("Failed to create validate pipeline:\n" + error_msg);
        }
        size_t parse_threads = parse_pipeline -> maxTotalThreadsPerThreadgroup();
        size_t validate_threads = validate_pipeline -> maxTotalThreadsPerThreadgroup();
        LOG_INFO(logger, "Parse pipeline: max {} threads/threadgroup", parse_threads);
        LOG_INFO(logger, "Validate pipeline: max {} threads/threadgroup", validate_threads);
        validate_func -> release();
        parse_func -> release();
        library -> release();
    }
    void create_buffers() {
        LOG_INFO(logger, "Allocating GPU buffers...");
        size_t request_size = batch_size * max_request_size;
        size_t parsed_size = batch_size * sizeof(GPUParsedRequest);
        size_t validation_size = batch_size * sizeof(uint32_t);
        LOG_INFO(logger, "  Request buffer: {:.4f} KB", request_size / 1024.0);
        LOG_INFO(logger, "  Parsed buffer: {:.4f} KB", parsed_size / 1024.0);
        LOG_INFO(logger, "  Validation buffer: {:.4f} KB", validation_size / 1024.0);
        // buffer 0: GPU is reading/processing
        // buffer 1: CPU is writing new data
        // buffer 2: CPU is reading results
        for (size_t i = 0; i < RING_SIZE; i++) {
            buffers.request_buffers[i] = device -> newBuffer(request_size, MTL::ResourceStorageModeShared);
            buffers.parsed_buffers[i] = device -> newBuffer(parsed_size, MTL::ResourceStorageModeShared);
            buffers.validation_buffers[i] = device -> newBuffer(validation_size, MTL::ResourceStorageModeShared);
            if (!buffers.request_buffers[i] || !buffers.parsed_buffers[i] || !buffers.validation_buffers[i]) { //check for alloc fails
                // clean up any successfully allocated buffers
                for (size_t j = 0; j <= i; j++) {
                    if (buffers.request_buffers[j]) buffers.request_buffers[j] -> release();
                    if (buffers.parsed_buffers[j]) buffers.parsed_buffers[j] -> release();
                    if (buffers.validation_buffers[j]) buffers.validation_buffers[j] -> release();
                }
                throw std::runtime_error("Failed to allocate GPU buffers. System may be out of memory or batch size is too large.");
            }
            LOG_INFO(logger, "  Allocated buffer set {}/{}", i + 1, RING_SIZE);
        }
    }
    size_t get_next_buffer_index() {
        // atomically increment and wrap around
        // thread-safe: multiple threads can call this simultaneously
        size_t idx = buffers.current_index.fetch_add(1, std::memory_order_relaxed);
        return idx % RING_SIZE;  // 0, 1, 2, 0, 1, 2, ...
    }
public:
    M2GPUHTTPParser(quill::Logger* logger, size_t max_req_size = HDE::server_config.MAX_BUFFER_SIZE, size_t batch_sz = HDE::server_config.batch_size) {
        if (HDE::server_config.log_level != MINIMAL) LOG_DEBUG(logger, "Initializing GPU...");
        this -> logger = logger;
        max_request_size = max_req_size;
        batch_size = batch_sz;
        device = MTL::CreateSystemDefaultDevice();
        if (!device)  [[unlikely]] throw std::runtime_error("Metal is not supported on this device.");
        if (!(device -> hasUnifiedMemory())) [[unlikely]] throw std::runtime_error("Device must support Unified Memory Architecture (UMA).");
        //if (!(device -> supportsFamily(MTL::GPUFamilyMetal4))) throw std::runtime_error("Device doesn't support Metal 4.");
        LOG_DEBUG(logger, "GPU Device: {}", device -> name() -> utf8String());
        LOG_DEBUG(logger, "Unified Memory: {}", device -> hasUnifiedMemory() ? "Yes (Apple Silicon)" : "No");
        LOG_DEBUG(logger, "Max Buffer Size: {:.4f} GB", device -> maxBufferLength() / 1024.0 / 1024.0 / 1024.0);
        command_queue = device -> newCommandQueue();
        if (!command_queue)  [[unlikely]] {
            device -> release();
            throw std::runtime_error("Failed to create command queue.");
        }
        if (HDE::server_config.log_level == FULL) LOG_DEBUG(logger, "Command queue initialized.");
        //compile shaders
        try {
            compile_shaders();
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) LOG_INFO(logger, "Compiled GPU shaders successfully");
        } catch (const std::exception& e) {
            command_queue -> release();
            device -> release();
            throw;
        }
        //alloc gpu buffers
        try {
            create_buffers();
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) LOG_INFO(logger, "GPU buffers allocated.");
        } catch (const std::exception& e) {
            parse_pipeline -> release();
            validate_pipeline -> release();
            command_queue -> release();
            device -> release();
            throw;
        }
        //request + parsed + validation buffers
        size_t total_memory = RING_SIZE * (batch_size * max_request_size + batch_size * sizeof(GPUParsedRequest) + batch_size * sizeof(uint32_t));
        if (HDE::server_config.log_level != MINIMAL) {
            LOG_DEBUG(logger, "Configuration:");
            LOG_DEBUG(logger, "  Max Request Size: {} bytes", max_request_size);
            LOG_DEBUG(logger, "  Batch Size: {} requests", batch_size);
            LOG_DEBUG(logger, "  Buffer Count: {} (triple buffering)", RING_SIZE);
            LOG_DEBUG(logger, "  Total GPU Memory: {:.4f} MB", total_memory / 1024.0 / 1024.0);
            LOG_INFO(logger, "==================================================");
        }
    }
    ~M2GPUHTTPParser() {
        LOG_INFO(logger, "Shutting down GPU Parser...");
        for (size_t i = 0; i < RING_SIZE; i++) {
            if (buffers.request_buffers[i]) {
                buffers.request_buffers[i] -> release();
            }
            if (buffers.parsed_buffers[i]) {
                buffers.parsed_buffers[i] -> release();
            }
            if (buffers.validation_buffers[i]) {
                buffers.validation_buffers[i] -> release();
            }
        }
        if (parse_pipeline) parse_pipeline -> release();
        if (validate_pipeline) validate_pipeline -> release();
        if (command_queue) command_queue -> release();
        if (device) device -> release();
        LOG_INFO(logger, "GPU Parser shutdown complete.");
    }
    //Thread-safe
    void process_batch_async(const char** requests, size_t count, GPUParsedRequest* results, uint32_t* validations, std::function<void(long req_count)> completion_handler) {
        if (count > batch_size)  [[unlikely]] {
            throw std::runtime_error("Batch size " + std::to_string(count) + " exceeds maximum " + std::to_string(batch_size));
        }
        if (count == 0) { //nothing to process
            completion_handler(count);
            return;
        }
        unsigned int max_size = static_cast<unsigned int>(max_request_size);
        if (HDE::server_config.log_level == FULL) {
            LOG_DEBUG(logger, "[Thread {}]: [GPU] Processing batch of {} requests (async)", HDE::get_thread_id_cached(), count);
        }
        size_t buffer_idx = get_next_buffer_index();
        __builtin_prefetch(&buffers, 0, 3);
        MTL::Buffer* request_buffer = buffers.request_buffers[buffer_idx];
        MTL::Buffer* parsed_buffer = buffers.parsed_buffers[buffer_idx];
        MTL::Buffer* validation_buffer = buffers.validation_buffers[buffer_idx];
        if (HDE::server_config.log_level == FULL) {
            LOG_DEBUG(logger, "[Thread {}]: [GPU] Using buffer slot {}", HDE::get_thread_id_cached(), buffer_idx);
        }
        __builtin_prefetch(request_buffer, 0, 3);
        char* gpu_memory = static_cast<char*>(request_buffer -> contents());
        //copy memory
        for (size_t i = 0; i < count; i++) {
            char* dest = gpu_memory + (i * max_request_size);
            size_t request_len = strlen(requests[i]);
            size_t copy_len = std::min(request_len, max_request_size - 1);
            memcpy(dest, requests[i], copy_len);
            dest[copy_len] = '\0';
        }
        request_buffer -> didModifyRange(NS::Range::Make(0, count * max_request_size)); //hint that buffer is modified
        if (HDE::server_config.log_level == FULL) {
            LOG_DEBUG(logger, "[Thread {}]: [GPU] Copied {} requests to GPU memory", HDE::get_thread_id_cached(), count);
        }
        MTL::CommandBuffer* cmd_buf = command_queue -> commandBuffer();
        if (!cmd_buf) [[unlikely]] throw std::runtime_error("Failed to create command buffer");
        __builtin_prefetch(cmd_buf, 0, 3);
        cmd_buf -> setLabel(NS::String::string("HTTP Parser Batch", NS::UTF8StringEncoding));
        MTL::ComputeCommandEncoder* encoder = cmd_buf -> computeCommandEncoder();
        if (!encoder) [[unlikely]] throw std::runtime_error("Failed to create compute encoder");
        __builtin_prefetch(encoder, 0, 3);
        encoder -> setComputePipelineState(parse_pipeline);
        encoder -> setBuffer(request_buffer, 0, 0);   // [[buffer(0)]]
        encoder -> setBuffer(parsed_buffer, 0, 1);    // [[buffer(1)]]
        encoder -> setBytes(&max_size, sizeof(unsigned int), 2);  // [[buffer(2)]], set constant value (max request size)
        MTL::Size grid_size = MTL::Size::Make(count, 1, 1); //calculate grid size (total threads needed)
        size_t max_threads = parse_pipeline -> maxTotalThreadsPerThreadgroup();
        size_t threads_per_group = std::min<size_t>(256, max_threads); // 256 is a good default for Apple GPUs
        threads_per_group = (threads_per_group / 32) * 32;
        if (threads_per_group == 0) threads_per_group = 32; //must be multiple of 32 (SIMD width on Apple GPUs)
        MTL::Size threadgroup_size = MTL::Size::Make(threads_per_group, 1, 1);
        __builtin_prefetch(encoder, 0, 3);
        encoder -> setThreadgroupMemoryLength(8192, 0); //allocate thread group memory
        encoder -> dispatchThreads(grid_size, threadgroup_size);
        if (HDE::server_config.log_level == FULL) {
            LOG_DEBUG(logger, "[Thread {}]: [GPU] Dispatched parse kernel: {} threads in groups of {}", HDE::get_thread_id_cached(), count, threads_per_group);
        }
        __builtin_prefetch(encoder, 0, 3);
        encoder -> setComputePipelineState(validate_pipeline);
        encoder -> setBuffer(request_buffer, 0, 0);      // [[buffer(0)]]
        encoder -> setBuffer(parsed_buffer, 0, 1);       // [[buffer(1)]]
        encoder -> setBuffer(validation_buffer, 0, 2);   // [[buffer(2)]]
        encoder -> setBytes(&max_size, sizeof(unsigned int), 3);  // [[buffer(3)]]
        max_threads = validate_pipeline -> maxTotalThreadsPerThreadgroup();
        threads_per_group = std::min<size_t>(256, max_threads);
        if (threads_per_group == 0) threads_per_group = 32;
        threadgroup_size = MTL::Size::Make(threads_per_group, 1, 1);
        __builtin_prefetch(encoder, 0, 3);
        encoder -> dispatchThreads(grid_size, threadgroup_size);
        if (HDE::server_config.log_level == FULL) {
            LOG_DEBUG(logger, "[Thread {}]: [GPU] Dispatched validate kernel", HDE::get_thread_id_cached());
        }
        encoder -> endEncoding();
        __builtin_prefetch(cmd_buf, 1, 3);
        cmd_buf -> addCompletedHandler([=, this](MTL::CommandBuffer* completed_buffer) -> void {
            MTL::CommandBufferStatus status = completed_buffer -> status();
            if (status == MTL::CommandBufferStatusError) [[unlikely]] {
                NS::Error* cmd_error = completed_buffer -> error();
                if (cmd_error) {
                    LOG_ERROR(logger, "[Thread {}]: [GPU] Command buffer failed: {}", HDE::get_thread_id_cached(), cmd_error -> localizedDescription() -> utf8String());
                } else {
                    LOG_ERROR(logger, "[Thread {}]: [GPU] Command buffer failed with unknown error", HDE::get_thread_id_cached());
                }
                completion_handler(count); // Still call completion handler to avoid deadlock
                return;
            }
            //read results from memory
            LOG_DEBUG(logger, "[Thread {}]: [GPU] before retrieving parsed_buffer", HDE::get_thread_id_cached());
            GPUParsedRequest* gpu_results =  static_cast<GPUParsedRequest*>(parsed_buffer -> contents());
            LOG_DEBUG(logger, "[Thread {}]: [GPU] before retrieving validation buffer", HDE::get_thread_id_cached());
            unsigned int* gpu_validations = static_cast<unsigned int*>(validation_buffer -> contents());
            LOG_DEBUG(logger, "[Thread {}]: [GPU] before memcpy() gpu_results", HDE::get_thread_id_cached());
            memcpy(results, gpu_results, count * sizeof(GPUParsedRequest));
            LOG_DEBUG(logger, "[Thread {}]: [GPU] before memcpy() gpu_validations", HDE::get_thread_id_cached());
            memcpy(validations, gpu_validations, count * sizeof(unsigned int));
            if (HDE::server_config.log_level == FULL) {
                LOG_DEBUG(logger, "[Thread {}]: [GPU] Copied {} results from buffer slot {}", HDE::get_thread_id_cached(), count, buffer_idx);
            }
            completion_handler(count);
            LOG_DEBUG(logger, "[Thread {}]: [GPU] memcpy() successful and completion_handler() called.", HDE::get_thread_id_cached());
        });
        cmd_buf -> commit(); //submnit work to GPU
        if (HDE::server_config.log_level == FULL) {
            LOG_DEBUG(logger, "[Thread {}]: [GPU] Command buffer submitted (async)", HDE::get_thread_id_cached());
        }
        //function ends here, completion handler will be called once GPU finishes
    }
    //Getters
    size_t get_max_batch_size() const { return batch_size; }
    size_t get_max_request_size() const { return max_request_size; }
    std::string get_device_info() const {
        if (!device) [[unlikely]] return "No Device.";
        return std::string(device -> name() -> utf8String());
    };
};
    inline std::unique_ptr<M2GPUHTTPParser> gpu_parser; 
};

//MPMC Lock Free Queue
template <typename T, size_t Capacity>
class OptimizedQueue {
    private:
        struct Slot {
            uint64_t sequence;
            alignas(T) std::byte storage[sizeof(T)];
            Slot() : sequence(0) {}
            T* data_ptr() noexcept {
                return std::launder(reinterpret_cast<T*>(storage));
            }
        };
        Slot* buffer;
        alignas(CACHE_LINE_SIZE) uint64_t enqueue_pos;
        char pad1[CACHE_LINE_SIZE - sizeof(uint64_t)];
        alignas(CACHE_LINE_SIZE) uint64_t dequeue_pos;
        char pad2[CACHE_LINE_SIZE - sizeof(uint64_t)];
        const uint64_t index_mask;
        uint64_t to_index(uint64_t pos) const noexcept {
            return pos & index_mask;
        }
    public:
        OptimizedQueue() : enqueue_pos(0), dequeue_pos(0), index_mask(Capacity - 1) {
            buffer = static_cast<Slot*>(::operator new(Capacity * sizeof(Slot), std::align_val_t{CACHE_LINE_SIZE}));
            for (size_t i = 0; i < Capacity; ++i) {
                new (&buffer[i]) Slot();
                arm64_atomics::store_relaxed(&buffer[i].sequence, i); //use relax store, single-threaded during init
            }
            for (size_t i = 0; i < Capacity; i += 16384 / sizeof(Slot)) {
                arm64_atomics::prefetch_stream_read(&buffer[i]); //prefault pages with streaming hint (won't use again during init)
            }
            arm64_atomics::dmb(); //ensure all initialization is visible
        }
        ~OptimizedQueue() {
            uint64_t deq_pos = arm64_atomics::load_relaxed(&dequeue_pos);
            uint64_t enq_pos = arm64_atomics::load_relaxed(&enqueue_pos);
            for (uint64_t i = 0; i < deq_pos; ++i) {
                buffer[to_index(i)].data_ptr() -> ~T();
            }
            for (size_t i = 0; i < Capacity; ++i) {
                buffer[i].~Slot();
            }
            ::operator delete(buffer, std::align_val_t{CACHE_LINE_SIZE});
        }
        OptimizedQueue(const OptimizedQueue&) = delete;
        OptimizedQueue& operator=(const OptimizedQueue&) = delete;
        bool enqueue(T&& value) noexcept(std::is_nothrow_move_constructible_v<T>) {
            uint64_t pos = arm64_atomics::fetch_add_explicit_llsc(&enqueue_pos, 1);
            uint64_t idx = to_index(pos);
            Slot& slot = buffer[idx];
            arm64_atomics::prefetch_write(&buffer[to_index(pos + 1)]);
            arm64_atomics::prefetch_write(&buffer[to_index(pos + 2)]);
            uint64_t seq;
            uint32_t spin_count = 0;
            for (;;) {
                seq = arm64_atomics::load_acquire(&slot.sequence);
                if (seq == pos) break;
                if (seq < pos && pos - seq >= Capacity) {
                    spin_count++;
                    if (spin_count < 64) {
                        arm64_atomics::cpu_yield();
                    } else if (spin_count < 256) {
                        for (int i = 0; i < 4; ++i) arm64_atomics::cpu_yield();
                    } else {
                        for (int i = 0; i < 16; ++i) arm64_atomics::cpu_yield();
                        if (spin_count > 1000) spin_count = 256;
                    }
                    continue;
                }
                arm64_atomics::cpu_yield();
            }
            arm64_atomics::prefetch_write(&slot);
            // Construct object
            new (slot.data_ptr()) T(std::move(value));
            // Release store to publish
            arm64_atomics::store_release(&slot.sequence, pos + 1);
            return true;
        }
        //overload for const refs
        bool enqueue(const T& value) noexcept(std::is_nothrow_copy_constructible_v<T>) {
            uint64_t pos = arm64_atomics::fetch_add_explicit_llsc(&enqueue_pos, 1);
            uint64_t idx = to_index(pos);
            Slot& slot = buffer[idx];
            arm64_atomics::prefetch_write(&buffer[to_index(pos + 1)]);
            arm64_atomics::prefetch_write(&buffer[to_index(pos + 2)]);
            uint64_t seq;
            for (;;) {
                seq = arm64_atomics::load_acquire(&slot.sequence);
                if (seq == pos) break;
                if (seq < pos && pos - seq >= Capacity) {
                    arm64_atomics::cpu_yield();
                    continue;
                }
                arm64_atomics::cpu_yield();
            }
            arm64_atomics::prefetch_write(&slot);
            new (slot.data_ptr()) T(value);
            arm64_atomics::store_release(&slot.sequence, pos + 1);
            return true;
        }
        bool dequeue(T& out_value) noexcept(std::is_nothrow_move_assignable_v<T>) {
            uint64_t pos = arm64_atomics::fetch_add_explicit_llsc(&dequeue_pos, 1);
            uint64_t idx = to_index(pos);
            Slot& slot = buffer[idx];
            arm64_atomics::prefetch_read(&buffer[to_index(pos + 1)]);
            arm64_atomics::prefetch_read(&buffer[to_index(pos + 2)]);
            uint64_t seq;
            for (;;) {
                seq = arm64_atomics::load_acquire(&slot.sequence);
                if (seq == pos + 1) break;
                if (seq < pos + 1 && pos + 1 - seq > Capacity) {
                    arm64_atomics::cpu_yield();
                    continue;
                }
                arm64_atomics::cpu_yield();
            }
            arm64_atomics::prefetch_read(&slot);
            out_value = std::move(*slot.data_ptr());
            slot.data_ptr() -> ~T();
            arm64_atomics::store_release(&slot.sequence, pos + Capacity);
            return true;
        }
        //batch operations, good for loop unrolling
        size_t enqueue_batch(T* values, size_t count) noexcept {
            if (count == 0) return 0;
            // Claim positions atomically
            uint64_t start_pos = arm64_atomics::fetch_add_explicit_llsc(&enqueue_pos, count);
            size_t enqueued = 0;
            // Manually unrolled loop - process 4 at a time
            size_t i = 0;
            for (; i + 3 < count; i += 4) {
                //prefetch 4 slots ahead & process all 4
                arm64_atomics::prefetch_write(&buffer[to_index(start_pos + i)]);
                arm64_atomics::prefetch_write(&buffer[to_index(start_pos + i + 1)]);
                arm64_atomics::prefetch_write(&buffer[to_index(start_pos + i + 2)]);
                arm64_atomics::prefetch_write(&buffer[to_index(start_pos + i + 3)]);
                for (int j = 0; j < 4; j++) {
                    uint64_t pos = start_pos + i + j;
                    Slot& slot = buffer[to_index(pos)];
                    uint64_t seq;
                    while ((seq = arm64_atomics::load_acquire(&slot.sequence)) != pos) {
                        if (seq < pos && pos - seq >= Capacity) {
                            goto batch_done;
                        }
                        arm64_atomics::cpu_yield();
                    }
                    new (slot.data_ptr()) T(std::move(values[i + j]));
                    arm64_atomics::store_release(&slot.sequence, pos + 1);
                    enqueued++;
                }
            }
            // Handle remaining items
            for (; i < count; i++) {
                uint64_t pos = start_pos + i;
                Slot& slot = buffer[to_index(pos)];
                uint64_t seq;
                while ((seq = arm64_atomics::load_acquire(&slot.sequence)) != pos) {
                    if (seq < pos && pos - seq >= Capacity) goto batch_done;
                    arm64_atomics::cpu_yield();
                }
                new (slot.data_ptr()) T(std::move(values[i]));
                arm64_atomics::store_release(&slot.sequence, pos + 1);
                enqueued++;
            }
        batch_done:
            return enqueued;
        }
        bool empty() const noexcept {
            // Use acquire loads to see latest state
            uint64_t deq = arm64_atomics::load_acquire(&dequeue_pos);
            uint64_t enq = arm64_atomics::load_acquire(&enqueue_pos);
            return deq >= enq;
        }
        size_t size() const noexcept {
            uint64_t deq = arm64_atomics::load_acquire(&dequeue_pos);
            uint64_t enq = arm64_atomics::load_acquire(&enqueue_pos);
            if (enq <= deq) return 0;
            return (enq - deq < Capacity) ? (enq - deq) : Capacity;
        }
};

//Runs on independent thread
void HDE::Server::accepter(HDE::AddressQueue& address_queue, quill::Logger* logger) {
    M2ThreadAffinity::pin_to_p_core(0);
    M2ThreadAffinity::set_qos_performance();
    std::unique_lock<std::mutex> init_lock(HDE::serverState.init_mutex);
    //std::unique_lock<std::mutex> addr_lock(HDE::serverState.address_queue_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [] {
        return HDE::serverState.finished_initialization.load(std::memory_order_acquire);
    });
    LOG_NOTICE(logger, "[Thread {}]: [Accepter] Initializing...", HDE::get_thread_id_cached());
    init_lock.unlock();
    char local_buf[HDE::server_config.MAX_BUFFER_SIZE];
    thread_local char ip_str[INET6_ADDRSTRLEN];
    thread_local int client_socket_fd;
    thread_local const size_t MAX_PACKET_SIZE = HDE::server_config.MAX_BUFFER_SIZE - 1;
    thread_local int res;
    thread_local int nodelay = 1;
    thread_local ssize_t bytesRead;
    //thread_local struct sockaddr_in address;
    thread_local struct timeval timeout = {5, 0}; //wait 5 seconds for client to send a response, closes when unresponsive
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
                if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) [[unlikely]] LOG_INFO(logger, "[Thread {}]: [Accepter] No activity in 5 seconds.", HDE::get_thread_id_cached());
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
            LOG_INFO(logger, "[Thread {}]: [Accepter] Waiting for requests...", HDE::get_thread_id_cached());
        }
        //__builtin_prefetch(&address, 1, 3);
        struct sockaddr_in address = get_socket() -> get_address(); //find a way to optimize this
        __builtin_prefetch(&client_socket_fd, 1, 3);
        __builtin_prefetch(&address, 0, 3);
        client_socket_fd = accept(get_socket() -> get_sock(), reinterpret_cast<struct sockaddr*>(&address), reinterpret_cast<socklen_t*>(&addrlen));
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Accepter] Checkpoint 1 reached.", HDE::get_thread_id_cached());
        }
        if (client_socket_fd < 0) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) LOG_ERROR(logger, "[Thread {}]: [Accepter] A client cannot connect to the server.", HDE::get_thread_id_cached());
            HDE::reportErrorMessage(logger);
            client_socket_fd = 0;
            continue;
        }
        if (setsockopt(client_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 && HDE::server_config.enable_slowloris_protection) [[unlikely]] {
            if (HDE::server_config.log_level == FULL) {
                LOG_ERROR(logger, "[Thread {}]: [Accepter] Failed to set socket timeout: {}", HDE::get_thread_id_cached(), strerror(errno));
            }
        }
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Accepter] Checkpoint 2 reached.", HDE::get_thread_id_cached());
        }
        __builtin_prefetch(&nodelay, 0, 3);
        if (setsockopt(client_socket_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0 && HDE::server_config.tcp_nodelay) [[unlikely]] { //send packets immediately when available, reduces latency
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] Failed to set TCP_NODELAY", HDE::get_thread_id_cached());
            }
        }
        __builtin_prefetch(&res, 1, 3);
        __builtin_prefetch(&ip_str, 1, 3);
        __builtin_prefetch(&address, 0, 3);
        res = getnameinfo(reinterpret_cast<struct sockaddr*>(&address), sizeof(address), ip_str, INET6_ADDRSTRLEN, nullptr, 0, NI_NUMERICHOST);
        if (res != 0) [[unlikely]] {
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] A client has an unknown IP address. The server will attempt to close the connection; and shuts it down if that fails.", HDE::get_thread_id_cached());
            }
            HDE::reportErrorMessage(logger);
            if (close(client_socket_fd) < 0) [[unlikely]] {
                __builtin_prefetch(&client_socket_fd, 0, 3);
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        if (HDE::server_config.log_level == FULL) {
            LOG_DEBUG(logger, "[Thread {}]: [Accepter] Checkpoint 3 reached.", HDE::get_thread_id_cached());
        }
        if (HDE::is_rate_limited(std::string(ip_str)) && HDE::server_config.enable_DoS_protection) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] Deteched possible DoS attempt from client {}. The server will attempt to close the connection, and shuts it if that fails.", HDE::get_thread_id_cached(), ip_str);
            }
            if (close(client_socket_fd) < 0) [[unlikely]] {
                __builtin_prefetch(&client_socket_fd, 0, 3);
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        __builtin_prefetch(&bytesRead, 1, 3);
        __builtin_prefetch(&local_buf, 1, 3);
        bytesRead = read(client_socket_fd, local_buf, sizeof(local_buf) - 1);
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Accepter] Checkpoint 4 reached.", HDE::get_thread_id_cached());
        }
        __builtin_prefetch(&bytesRead, 0, 3);
        if (bytesRead > 0 && bytesRead < sizeof(local_buf) - 1) [[likely]] {
            __builtin_prefetch(&local_buf, 1, 3);
            local_buf[bytesRead] = '\0'; //null terminator, prevents buffer overflows
            if (HDE::server_config.log_level == FULL) {
                LOG_DEBUG(logger, "[Thread {}]: [Accepter] About to acquire address_queue_mutex in .emplate_response()", HDE::get_thread_id_cached());
            }
            __builtin_prefetch(&local_buf, 0, 3);
            Request req(client_socket_fd, std::string(local_buf, bytesRead)); //optimize obj creation
            while (!address_queue.enqueue(std::move(req))) std::this_thread::yield(); //arm64 yield instruction
            HDE::server_metrics.add_to_bytes_received(bytesRead);
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                __builtin_prefetch(&local_buf, 0, 3);
                LOG_DEBUG(logger, "[Thread {}]: [Accepter] Received data from {}:\n{}", HDE::get_thread_id_cached(), ip_str, std::string(local_buf));
            } else if (HDE::server_config.log_level == DECREASED) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] Client {} is connected.", HDE::get_thread_id_cached(), ip_str);
            }
            continue;
        } else if (bytesRead == 0) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] A client is disconnected to the server. No bytes are read. IP: {}. The server will attempt to close the connection, and shuts it down if that fails.", HDE::get_thread_id_cached(), ip_str);
            }
            HDE::reportErrorMessage(logger);
            if (close(client_socket_fd) < 0) [[unlikely]] {
                __builtin_prefetch(&client_socket_fd, 0, 3);
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        } else if (bytesRead >= sizeof(local_buf) - 1) [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [Accepter] A client has a packet that could trigger a buffer overflow, either by an oversized request or a DoS attempt. Client IP: {}. Request size: {}. The server will attempt to close the connection, and shuts it down if that fails.", HDE::get_thread_id_cached(), ip_str, bytesRead);
            }
            if (close(client_socket_fd) < 0) [[unlikely]] {
                __builtin_prefetch(&client_socket_fd, 0, 3);
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        } else {
            if (errno == EAGAIN) [[unlikely]] {
                if (HDE::server_config.log_level != MINIMAL) {
                    LOG_NOTICE(logger, "[Thread {}]: [Accepter] Socket read timeout - possible Slowloris attack. The server will attempt to close the connection, and shuts it down if that fails.", HDE::get_thread_id_cached());
                }
                if (close(client_socket_fd) < 0) [[unlikely]] {
                    __builtin_prefetch(&client_socket_fd, 0, 3);
                    shutdown(client_socket_fd, SHUT_RDWR);
                }
                continue;
            }
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_ERROR(logger, "[Thread {}]: [Accepter] General read error encountered. The server will attempt to close the connection, and shuts it down if that fails.", HDE::get_thread_id_cached());
            }
            HDE::reportErrorMessage(logger);
            if (close(client_socket_fd) < 0) [[unlikely]] {
                __builtin_prefetch(&client_socket_fd, 0, 3);
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        if (HDE::connection_history.size() > 1000000) {
            __builtin_prefetch(&connection_history, 1, 3);
            connection_history.clear();
        }
        client_socket_fd = 0;
    }
    /*#ifdef __APPLE__
        close(kq);
    #elif __linux__
        close(epoll_fd);
    #endif*/
    LOG_NOTICE(logger, "[Thread {}]: [Accepter] Accepter loop terminated.", HDE::get_thread_id_cached());
    return;
}
//Runs on independent thread
//Retrieve the incoming request from AddressQueue object, then load the processed request into the ResponderQueue object
//Function is computation-heavy, allocate more threads
//Now comes with GPU-Accelerated processing
void HDE::Server::handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue, quill::Logger* logger) {
    static std::atomic<int> handler_core_id{1};
    int my_core = handler_core_id.fetch_add(1, std::memory_order_relaxed);
    M2ThreadAffinity::pin_to_p_core(my_core); //fix ts bruh
    M2ThreadAffinity::set_qos_performance();
    std::unique_lock<std::mutex> init_lock(HDE::serverState.init_mutex);
    //std::unique_lock<std::mutex> addr_lock(HDE::serverState.address_queue_mutex, std::defer_lock);
    //std::unique_lock<std::mutex> resp_lock(HDE::serverState.responder_queue_mutex, std::defer_lock);
    std::unique_lock<std::mutex> cv_lock(HDE::serverState.address_cv_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [] { 
        return HDE::serverState.finished_initialization.load(std::memory_order_acquire);
    });
    LOG_NOTICE(logger, "[Thread {}]: [GPU-Accelerated Handler] Initializing...", HDE::get_thread_id_cached());
    init_lock.unlock();
    //Alloc once use forever principle
    thread_local constexpr size_t BATCH_SIZE = HDE::server_config.batch_size;
    thread_local unsigned int validation_results[BATCH_SIZE];
    thread_local Request batch[BATCH_SIZE];
    thread_local const char* request_ptrs[BATCH_SIZE];
    thread_local GPUParsedRequest parsed_results[BATCH_SIZE];
    thread_local size_t batch_count = 0;
    //actually can optimize gpu_busy to use memory_order_acquire instead of seq_cst
    volatile std::atomic<bool> gpu_busy{false};
    thread_local std::chrono::steady_clock::time_point gpu_start;
    thread_local std::chrono::steady_clock::time_point gpu_end;
    thread_local std::chrono::microseconds gpu_time;
    thread_local unsigned int is_valid; //try to not modify during runtime
    thread_local Response resp;
    thread_local std::string_view path;
    thread_local std::string_view response;
    thread_local bool is_404;
    for (;;) {
        if (HDE::serverState.stop_server.load(std::memory_order_relaxed)) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [GPU-Accelerated Handler] Terminating handler loop...", HDE::get_thread_id_cached());
            break;
        }
        if (HDE::server_config.log_level != MINIMAL) {
            LOG_INFO(logger, "[Thread {}]: [GPU-Accelerated Handler] Waiting and bundling tasks...", HDE::get_thread_id_cached());
        }
        batch_count = 0;
        while (batch_count < BATCH_SIZE) {
            while (!address_queue.dequeue(batch[batch_count])) __builtin_arm_yield();
            /*if (!address_queue.dequeue(batch[batch_count])) { //wth is this
                if (batch_count > 0) break;  // Have some, process them
                //__builtin_arm_yield();
                continue;
            }*/
            if (batch[batch_count].location == 0) [[unlikely]] continue;
            request_ptrs[batch_count] = batch[batch_count].msg.c_str();
            batch_count++;
            if (!gpu_busy.load(std::memory_order_seq_cst)) {
                if (batch_count >= HDE::server_config.minimum_batch_size) break;
            }
            //refactor this if's part
            if (batch_count == BATCH_SIZE - 1) break; //max batch size, too much, have to break to prevent exception
            if (batch_count < HDE::server_config.minimum_batch_size) break;
            if (address_queue.size() < 256) break; //queue could be refilling same rate as polling, quit to same sum latency
        }
        if (batch_count == 0) continue;
        if (HDE::server_config.enable_perf_timing_telemetry) {
            __builtin_prefetch(&gpu_start, 1, 3);
            gpu_start = std::chrono::high_resolution_clock::now();
        }
        if (HDE::server_config.log_level != MINIMAL || HDE::server_config.log_level != DECREASED) {
            LOG_INFO(logger, "[Thread {}]: [GPU-Accelerated Handler] A valid batch of {} requests has formed. Processing...", HDE::get_thread_id_cached(), batch_count);
        }
        while (gpu_busy.load(std::memory_order_acquire)) std::this_thread::yield(); // Wait for GPU to finish current batch
        gpu_busy.store(true, std::memory_order_release);
        __builtin_prefetch(&gpu_parser, 0, 3);
        gpu_parser -> process_batch_async(request_ptrs, batch_count, parsed_results, validation_results, [&](long int req_count) -> void {
            if (req_count < 0) [[unlikely]] {
                LOG_ERROR(logger, "[Thread {}]: [GPU-Accelerated Handler] Invalid argument req_count for lambda [&](int req_count) -> void", HDE::get_thread_id_cached());
            }
            LOG_DEBUG(logger, "here");
            if (HDE::server_config.enable_perf_timing_telemetry) {
                __builtin_prefetch(&gpu_end, 1, 3);
                gpu_end = std::chrono::high_resolution_clock::now();
                __builtin_prefetch(&gpu_time, 1, 3);
                gpu_time = std::chrono::duration_cast<std::chrono::microseconds>(gpu_end - gpu_start);
                if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                    LOG_INFO(logger, "[Thread {}]: [GPU-Accelerated Handler] Processed {} requests in {} microseconds (GPU)", HDE::get_thread_id_cached(), req_count, gpu_time.count());
                }
            }
            gpu_busy.store(false, std::memory_order_release);
            if (HDE::server_config.log_level == FULL) {
                LOG_DEBUG(logger, "[Thread {}]: [GPU-Accelerated Handler]: [completion handler] gpu_busy: {}", HDE::get_thread_id_cached(), gpu_busy.load(std::memory_order_seq_cst));
            }
        });
        while (gpu_busy.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        if (HDE::server_config.log_level == FULL) {
            LOG_INFO(logger, "[Thread {}]: [GPU-Accelerated Handler] Batch finished. Now post-processing", HDE::get_thread_id_cached());
        }
        //Post-Processing
        LOG_DEBUG(logger, "[Thread {}]: [GPU-Accelerated Handler] (2) batch_count: {}", HDE::get_thread_id_cached(), batch_count);
        #pragma clang loop vectorize(disable)
        for (size_t i = 0; i < batch_count; i++) {
            const GPUParsedRequest& parsed = parsed_results[i];
            __builtin_prefetch(&is_valid, 1, 3);
            is_valid = validation_results[i];
            __builtin_prefetch(&parsed, 0, 3);
            if (HDE::server_config.show_parsed_gpu_req && HDE::server_config.log_level == FULL) {
                LOG_DEBUG(logger, "[Thread{}]: [GPU-Accelerated Handler] parsed.method: {}", HDE::get_thread_id_cached(), parsed.method);
                LOG_DEBUG(logger, "[Thread{}]: [GPU-Accelerated Handler] parsed.path_offset: {}", HDE::get_thread_id_cached(), parsed.path_offset);
                LOG_DEBUG(logger, "[Thread{}]: [GPU-Accelerated Handler] parsed.path_length: {}", HDE::get_thread_id_cached(), parsed.path_length);
                LOG_DEBUG(logger, "[Thread{}]: [GPU-Accelerated Handler] parsed.version_valid: {}", HDE::get_thread_id_cached(), parsed.version_valid);
                //LOG_DEBUG(logger, "[Thread{}]: [GPU-Accelerated Handler] parsed.content_length: {}", HDE::get_thread_id_cached(), parsed.content_length);
                LOG_DEBUG(logger, "[Thread{}]: [GPU-Accelerated Handler] parsed.is_valid: {}", HDE::get_thread_id_cached(), parsed.is_valid);
            }
            if (!parsed.is_valid || !is_valid) [[unlikely]] { //bad request
                __builtin_prefetch(&batch, 0, 2);
                __builtin_prefetch(&resp, 1, 3);
                resp = {batch[i].location, bad_request_response};
                while (!responder_queue.enqueue(std::move(resp))) __builtin_arm_yield();
                if (HDE::server_config.log_level == FULL && HDE::server_config.show_req) {
                    LOG_DEBUG(logger, "[Thread {}]: [GPU-Accelerated Handler] resp (400) : {}, request enqueued.", HDE::get_thread_id_cached(), resp.msg);
                }
                __builtin_prefetch(&(batch[i].msg), 0, 2);
                __builtin_prefetch(&HDE::server_metrics, 1, 3);
                HDE::server_metrics.record_request(false, batch[i].msg.length(), bad_request_response.length());
                if (HDE::server_config.log_level != MINIMAL) {
                    LOG_NOTICE(logger, "[Thread {}]: [GPU-Accelerated Handler] A client's request is malformed. (400)", HDE::get_thread_id_cached());
                }
                continue;
            }
            if (parsed.method > 3) [[unlikely]] {  // method not allowed
                __builtin_prefetch(&batch, 0, 2);
                __builtin_prefetch(&resp, 1, 3);
                resp = {batch[i].location, method_not_allowed_response};
                while (!responder_queue.enqueue(std::move(resp))) __builtin_arm_yield();
                if (HDE::server_config.log_level == FULL && HDE::server_config.show_req) {
                    LOG_DEBUG(logger, "[Thread {}]: [GPU-Accelerated Handler] resp (405) : {}, request enqueued.", HDE::get_thread_id_cached(), resp.msg);
                }
                __builtin_prefetch(&(batch[i].msg), 0, 2);
                __builtin_prefetch(&HDE::server_metrics, 1, 3);
                HDE::server_metrics.record_request(false, batch[i].msg.length(), method_not_allowed_response.length());
                if (HDE::server_config.log_level != MINIMAL) {
                    LOG_NOTICE(logger, "[Thread {}]: [GPU-Accelerated Handler] A client's request contains an illegal method. (405)", HDE::get_thread_id_cached());
                }
                continue;
            }
            //ya might need a 493 right here
            __builtin_prefetch(&batch, 0, 2);
            __builtin_prefetch(&parsed, 1, 2);
            __builtin_prefetch(&path, 1, 3);
            path = std::string_view(batch[i].msg.c_str() + parsed.path_offset, parsed.path_length);
            //checks for special requests/paths
            //if we have any other special requests being added here is the place to add the checks for it.
            if (path.starts_with("/admin")) [[unlikely]] {
                auto headers = HDE::HTTPParser::parse_headers(batch[i].msg);
                auto auth_it = headers.find("Authorization");
                if (!admin_config.admin_enabled || (auth_it == headers.end() || !AdminAuth::check_auth(auth_it -> second))) { //401
                    resp = {batch[i].location, unauthorized_response};
                    while (!responder_queue.enqueue(std::move(resp))) arm64_atomics::cpu_yield();
                    if (HDE::server_config.log_level == FULL && HDE::server_config.show_req) {
                        LOG_DEBUG(logger, "[Thread {}]: [GPU-Accelerated Handler] resp (401) : {}, request enqueued.", HDE::get_thread_id_cached(), resp.msg);
                    }
                    __builtin_prefetch(&(batch[i].msg), 0, 2);
                    __builtin_prefetch(&HDE::server_metrics, 1, 3);
                    HDE::server_metrics.record_request(false, batch[i].msg.length(), unauthorized_response.length());
                    if (HDE::server_config.log_level != MINIMAL) {
                        LOG_NOTICE(logger, "[Thread {}]: [GPU-Accelerated Handler] A client is not authorized to access the admin panel. (401)", HDE::get_thread_id_cached());
                    }
                    continue;
                }
                if (path == "/admin/metrics") [[likely]] {
                    std::string&& result_json = server_metrics.get_metrics_json();
                    resp = {batch[i].location, std::format(
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: {}\r\n"
                        "Connection: close\r\n"
                        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
                        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
                        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
                        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
                        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
                        "\r\n{}", result_json.length(), result_json)};
                } else if (path == "/admin/cache/reload" && parsed.method == 1) [[unlikely]] {
                    std::string&& result_json = std::format("{{\"files_loaded\": {}}}", cache.reload_all_files(logger));
                    resp = {batch[i].location, std::format(
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: {}\r\n"
                        "Connection: close\r\n"
                        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
                        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
                        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
                        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
                        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
                        "\r\n{}", result_json.length(), result_json
                    )};
                } else if (path == "admin/cache/clear" && parsed.method == 1) [[unlikely]] {
                    cache.clear_cache();
                    std::string&& result_json = "{\"status\": \"cleared\"}";
                    resp = {batch[i].location, std::format(
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: {}\r\n"
                        "Connection: close\r\n"
                        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
                        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
                        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
                        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
                        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
                        "\r\n{}", result_json.length(), result_json
                    )};
                } else if (path == "/admin/shutdown" && parsed.method == 1) [[unlikely]] {
                    LOG_CRITICAL(logger, "[Thread {}]: [Handler] Shutdown requested from admin panel", HDE::get_thread_id_cached());
                    std::string&& result_json = "{\"status\": \"shutting_down\"}";
                    resp = {batch[i].location, std::format(
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: {}\r\n"
                        "Connection: close\r\n"
                        "X-Content-Type-Options: nosniff\r\n"              // Prevent MIME sniffing
                        "X-Frame-Options: DENY\r\n"                        // Prevent clickjacking
                        "X-XSS-Protection: 1; mode=block\r\n"              // XSS protection
                        "Content-Security-Policy: default-src 'self'\r\n"  // CSP
                        "Strict-Transport-Security: max-age=31536000\r\n"  // Force HTTPS (if using TLS)
                        "\r\n{}", result_json.length(), result_json
                    )};
                    std::jthread([&address_queue, &responder_queue]() {
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        HDE::clean_server_shutdown(address_queue, responder_queue);
                        //gpu_parser unique pointer automatically calls destructor when out of scope, not needed here.
                    });
                } else {
                    __builtin_prefetch((cache.get_response("/admin").data()), 0, 2);
                    __builtin_prefetch(&response, 1, 3);
                    response = cache.get_response("/admin");
                    __builtin_prefetch(&batch, 0, 2);
                    __builtin_prefetch(&response, 0, 2);
                    __builtin_prefetch(&resp, 1, 3);
                    resp = {batch[i].location, response};
                }
            } else {
                //for other file paths
                __builtin_prefetch((cache.get_response(path).data()), 0, 2);
                __builtin_prefetch(&response, 1, 3);
                response = cache.get_response(path);
                //__builtin_prefetch(&batch, 0, 2);
                __builtin_prefetch(&response, 0, 2);
                __builtin_prefetch(&resp, 1, 3);
                resp = {batch[i].location, response}; // building response
            }
            if (HDE::server_config.log_level == FULL && HDE::server_config.show_req) {
                LOG_DEBUG(logger, "[Thread {}]: [GPU-Accelerated Handler] response: {}", HDE::get_thread_id_cached(), response);
            }
            if (HDE::server_config.log_level == FULL && HDE::server_config.log_resp_before_send) {
                LOG_DEBUG(logger, "[Thread {}]: [GPU-Accelerated Handler] resp.destination: {}", HDE::get_thread_id_cached(), resp.destination);
                LOG_DEBUG(logger, "[Thread {}]: [GPU-Accelerated Handler] resp.msg: {}", HDE::get_thread_id_cached(), resp.msg);
            }
            while (!responder_queue.enqueue(std::move(resp))) std::this_thread::yield(); //load into queue
            if (HDE::server_config.log_level == FULL) {
                LOG_DEBUG(logger, "[Thread {}]: [GPU-Accelerated Handler] Response successfully added to queue.", HDE::get_thread_id_cached());
            }
            if (response.starts_with("HTTP/1.1 404") && HDE::server_config.log_level != MINIMAL) {
                LOG_NOTICE(logger, "[Thread {}]: [GPU-Accelerated Handler] A client tried to access non-existent resources. (404)", HDE::get_thread_id_cached());
            }
            __builtin_prefetch(&batch, 0, 2);
            __builtin_prefetch(&HDE::server_metrics, 1, 3);
            HDE::server_metrics.record_request(!response.starts_with("HTTP/1.1 404"), batch[i].msg.length(), response.length());
        }
        if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
            LOG_INFO(logger, "[Thread {}]: [GPU-Accelerated Handler] Completed batch of {} requests", HDE::get_thread_id_cached(), batch_count);
        }
        //batch_count = 0; //reset for next batch
    }
    LOG_NOTICE(logger, "[Thread {}]: [GPU-Accelerated Handler] Handler loop terminated.", HDE::get_thread_id_cached());
    return;
}
//Runs on independent thread
void HDE::Server::responder(HDE::ResponderQueue& response, quill::Logger* logger) {
    M2ThreadAffinity::pin_to_e_core(0);
    M2ThreadAffinity::set_qos_efficiency(); //change this later when fully ported to GPU-accelerated request parsing
    std::unique_lock<std::mutex> init_lock(HDE::serverState.init_mutex);
    std::unique_lock<std::mutex> cv_lock(HDE::serverState.response_cv_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [] {
        return HDE::serverState.finished_initialization.load(std::memory_order_acquire);
    });
    LOG_NOTICE(logger, "[Thread {}]: [Responder] Initializing...", HDE::get_thread_id_cached());
    init_lock.unlock();
    thread_local struct Response client;
    thread_local const char* msg; //= (char*)mmap(nullptr, HDE::server_config.max_pos_file_size * 1048576, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    thread_local ssize_t res;
    thread_local size_t total_sent = 0;
    thread_local size_t total_length;
    thread_local constexpr int MAX_RETRIES = HDE::server_config.max_retries_when_send_fail;
    thread_local int retry_count = 0;
    thread_local bool send_success = false;
    auto handle_send_error = [&](int error_code) -> bool {
        switch (error_code) {
            case EAGAIN:
                if (HDE::server_config.log_level == FULL) [[unlikely]] {
                    LOG_INFO(logger, "[Thread {}]: [Responder] Send buffer full, retrying...", HDE::get_thread_id_cached());
                }
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                return true;
            case EPIPE:
            case ECONNRESET:
                // Connection closed by client - expected, don't retry
                if (HDE::server_config.log_level == FULL) [[unlikely]] {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] Connection closed by peer", HDE::get_thread_id_cached());
                }
                return false;
                
            case ETIMEDOUT:
                // Network timeout - retry once
                if (HDE::server_config.log_level == FULL) [[unlikely]] {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] Network timeout", HDE::get_thread_id_cached());
                }
                return false;
                
            case EINTR:
                if (HDE::server_config.log_level == FULL) [[unlikely]] {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] Interrupted, retrying...", HDE::get_thread_id_cached());
                }
                return true;
                
            case EBADF:
            case EINVAL:
                // Bad file descriptor or invalid socket - programming error
                if (HDE::server_config.log_level != MINIMAL) [[unlikely]] {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] Invalid socket (fd={})", HDE::get_thread_id_cached(), client.destination);
                    HDE::reportErrorMessage(logger);
                }
                return false; // Give up
                
            case ENOMEM:
                // Out of memory - serious, but might be temporary
                if (HDE::server_config.log_level != MINIMAL) [[unlikely]] {
                    LOG_CRITICAL(logger, "[Thread {}]: [Responder] Out of memory!", HDE::get_thread_id_cached());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                return true; // Retry after brief pause
                
            default:
                // Unknown error
                if (HDE::server_config.log_level != MINIMAL) [[unlikely]] {
                    LOG_CRITICAL(logger, "[Thread {}]: [Responder] Unknown error: {}", HDE::get_thread_id_cached(), strerror(error_code));
                }
                return false; // Give up on unknown errors
        }
    };
    for (;;) {
        if (HDE::serverState.stop_server.load(std::memory_order_relaxed)) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [Responder] Terminating responder loop...", HDE::get_thread_id_cached());
            break;
        }
        /*{
            if (HDE::server_config.log_level == FULL) LOG_DEBUG(logger, "[Thread {}]: [Responder] Acquired responder_cv_mutex", HDE::get_thread_id_cached());
            if (HDE::server_config.log_level != MINIMAL) LOG_NOTICE(logger, "[Thread {}]: [Responder] Waiting for tasks...", HDE::get_thread_id_cached());
            cv_lock.lock();
            resp_in_res_queue.wait(cv_lock, [&response] {
                return HDE::serverState.stop_server.load(std::memory_order_acquire) || !response.empty();
            });
            cv_lock.unlock();
        }*/
        if (HDE::serverState.stop_server.load(std::memory_order_seq_cst)) [[unlikely]] continue;
        //__builtin_prefetch(&client, 1, 3);
        while (!response.dequeue(client)) __builtin_arm_yield();
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Responder] Information extracted from queue.", HDE::get_thread_id_cached());
        }
        if (client == Response{}) [[unlikely]] continue;
        __builtin_prefetch(msg, 1, 3);
        msg = client.msg.c_str();
        total_sent = 0;
        total_length = client.msg.length();
        if (HDE::server_config.log_level != MINIMAL) {
            LOG_INFO(logger, "[Thread {}]: [Responder] Received data from [Handler]. Processing...", HDE::get_thread_id_cached());
        }
        retry_count = 0;
        send_success = false;
        while (total_sent < total_length) {
            __builtin_prefetch(&client, 0, 3);
            __builtin_prefetch(msg, 0, 3);
            res = send(client.destination, msg, client.msg.length(), MSG_NOSIGNAL);
            if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                LOG_INFO(logger, "[Thread {}]: [Responder] Result of variable <res>: {}", HDE::get_thread_id_cached(), std::to_string(res));
            }
            if (HDE::server_config.log_level == FULL) [[unlikely]] {
                LOG_DEBUG(logger, "[Thread {}]: [Responder] Checkpooint 2 reached.", HDE::get_thread_id_cached());
            }
            if (res < 0) [[unlikely]] {
                //case where the server failed to send the message
                if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                    LOG_ERROR(logger, "[Thread {}]: [Responder] ERROR: A client failed to receive the data.", HDE::get_thread_id_cached());
                }
                int error_code = errno;
                if (handle_send_error(error_code) && retry_count < MAX_RETRIES) {
                    retry_count++;
                    if (HDE::server_config.log_level == FULL) [[unlikely]] {
                        LOG_NOTICE(logger, "[Thread {}]: [Responder] Retry {}/{}", HDE::get_thread_id_cached(), retry_count, MAX_RETRIES);
                    }
                    continue;
                } else {
                    if (HDE::server_config.log_level != MINIMAL) [[unlikely]] {
                        LOG_ERROR(logger, "[Thread {}]: [Responder] Failed to send after {} retries", HDE::get_thread_id_cached(), retry_count);
                    }
                    break;
                }
            } else if (res > 0) [[likely]] {
                //successful tramission
                total_sent += res;
                retry_count = 0;
                if (HDE::server_config.log_level != MINIMAL) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] Successful data transmissiont to the client.", HDE::get_thread_id_cached());
                }
                if (total_sent >= total_length) {
                    send_success = true;
                    break;
                }
            } else if (res == 0) [[unlikely]] {
                //requested to write 0 bytes. typically not an error, but log this event
                if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
                    LOGV_NOTICE(logger, "[Thread {}]: [Responder] 0 bytes sent to the client. Either they requested 0 bytes or this could be an internal server error causing no bytes to be sent.", HDE::get_thread_id_cached());
                }
                break;
            }
        }
        if (HDE::server_config.log_level == FULL) [[unlikely]] {
            LOG_DEBUG(logger, "[Thread {}]: [Responder] Checkpoint 2 reached.", HDE::get_thread_id_cached());
        }
        if (send_success) [[likely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_INFO(logger, "[Thread {}]: [Responder] Successfully sent {} bytes", HDE::get_thread_id_cached(), total_sent);
            }
            HDE::server_metrics.record_request(true, 0, total_sent);
        } else [[unlikely]] {
            if (HDE::server_config.log_level != MINIMAL) {
                LOG_ERROR(logger, "[Thread {}]: [Responder] Failed to send complete response ({}/{} bytes)", HDE::get_thread_id_cached(), total_sent, total_length);
            }
            HDE::server_metrics.record_request(false, 0, total_sent);
        }
        __builtin_prefetch(&client, 0, 3);
        if (close(client.destination) < 0) [[unlikely]] {
            if (HDE::server_config.log_level == FULL) {
                LOG_ERROR(logger, "[Thread {}]: [Responder] An error occured while trying to close the connection. The server will force a shut down.", HDE::get_thread_id_cached());
            }
            HDE::reportErrorMessage(logger);
            __builtin_prefetch(&client, 0, 3);
            HDE::Server::logClientInfo("Responder", client.msg, logger);
            shutdown(client.destination, SHUT_RDWR);
        }
        if (HDE::server_config.log_level == FULL || HDE::server_config.log_level == DEFAULT) {
            LOG_INFO(logger, "========================= Log Separator =========================");
        }
        else if ((HDE::server_config.log_level == MINIMAL || HDE::server_config.log_level == DECREASED) && !HDE::server_config.disable_logging) {
            LOG_INFO(logger, "A client is processed by the server.");
        }
        continue;
    }
    LOG_NOTICE(logger, "[Thread {}]: [Responder] Responder loop terminated.", HDE::get_thread_id_cached());
    return;
}

void HDE::Server::launch(quill::Logger* logger) {
    //Checking server configurations during start up
    asm volatile("" ::: "memory"); //prevents the compiler from reordering memory operations, yes you can write asm inside c++
    //asm volatile("");
    if (HDE::server_config.totalUsedThreads > HDE::NUM_THREADS && !HDE::server_config.disable_warnings) [[unlikely]] {
        LOG_WARNING(logger, "[Thread {}]: [Main Thread] WARNING: totalUsedThreads is more than the amount of threads in the system, 8. This may render other performance optimizations such as CPU core pinning useless", HDE::get_thread_id_cached(), HDE::server_config.totalUsedThreads, HDE::NUM_THREADS);
    } else if ((HDE::server_config.threadsForAccepter > HDE::NUM_THREADS - 1 || HDE::server_config.threadsForResponder > HDE::NUM_THREADS - 1) && !HDE::server_config.disable_warnings) [[unlikely]] {
        LOG_WARNING(logger, "[Thread {}]: [Main Thread] WARNING: The allocated threads for one or more of the tasks exceeds the system thread count, 8. This may render other performance optimizations such as CPU core pinning useless", HDE::get_thread_id_cached(), std::to_string(HDE::NUM_THREADS - 2));
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.threadsForAccepter < 1 || HDE::server_config.threadsForResponder < 1) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The minimum value for each tasks must be 1 threads.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.totalUsedThreads < 2) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The minimum value for total used threads is 3. The amount allocated: {}", HDE::get_thread_id_cached(), std::to_string(HDE::server_config.totalUsedThreads));
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.queueCount < 1) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid queueCount configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.MAX_CONNECTIONS_PER_SECOND < 1) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid MAX_CONNECTIONS_PER_SECOND configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.MAX_ADDRESS_QUEUE_SIZE < 0) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Invalid server_config.MAX_ADDRESS_QUEUE_SIZE configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::server_config.MAX_RESPONSES_QUEUE_SIZE < 0) {
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
    if (!HDE::server_config.disable_warnings) {
        if (HDE::server_config.MAX_BUFFER_SIZE < 30000 && HDE::server_config.MAX_BUFFER_SIZE > 500) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [Main Thread] WARNING: BUFFER_SIZE might be insufficient to receive client requests.", HDE::get_thread_id_cached());
        } else if (HDE::server_config.MAX_ADDRESS_QUEUE_SIZE < 10000) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [Main Thread] ADVICE: It is recommended to have server_config.MAX_ADDRESS_QUEUE_SIZE more than 10000, in case the amount of requests backs up during peaj/extreme loads.", HDE::get_thread_id_cached());
        } else if (HDE::server_config.MAX_RESPONSES_QUEUE_SIZE < 10000) [[unlikely]] {
            LOG_NOTICE(logger, "[Thread {}]: [Main Thread] ADVICE: It is recommended to have max_responses_queue_size more than 10000, in case the amount of responses backs up during peak/extreme loads.", HDE::get_thread_id_cached());
        }
    }
    try {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Initializing GPU parser...", HDE::get_thread_id_cached());
        gpu_parser = std::make_unique<M2GPUHTTPParser>(logger, HDE::server_config.MAX_BUFFER_SIZE, 256);
        LOG_INFO(logger, "[Thread {}]: [Main Thread] GPU parser initialized successfully", HDE::get_thread_id_cached());
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Device: {}", HDE::get_thread_id_cached(), gpu_parser -> get_device_info());
        
    } catch (const std::exception& e) {
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] GPU parser initialization failed: {}", HDE::get_thread_id_cached(), e.what());
        LOG_ERROR(logger, "[Thread {}]: [Main Thread] Server cannot start without GPU acceleration", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    }
    cache.load_static_files(file_routes_list, logger);
    //Configuring socket options
    int opt = 1;
    if (HDE::server_config.reuse_address) setsockopt(get_socket() -> get_sock(), SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    if (HDE::server_config.receive_buffer_size) setsockopt(get_socket() -> get_sock(), SOL_SOCKET, SO_RCVBUF, &HDE::server_config.MAX_BUFFER_SIZE, sizeof(HDE::server_config.MAX_BUFFER_SIZE));
    if (HDE::server_config.send_buffer_size) setsockopt(get_socket() -> get_sock(), SOL_SOCKET, SO_SNDBUF, &HDE::server_config.MAX_BUFFER_SIZE, sizeof(HDE::server_config.MAX_BUFFER_SIZE));
    #ifdef __APPLE__
        int flags = fcntl(get_socket() -> get_sock(), F_GETFL, 0) ;
        if (HDE::server_config.tcp_fast_open) setsockopt(get_socket() -> get_sock(), IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));
        //if (HDE::server_config.non_blocking_socket) fcntl(get_socket() -> get_sock(), F_SETFL, flags | O_NONBLOCK);
        if (HDE::server_config.no_sigpipe_server) setsockopt(get_socket() -> get_sock(), SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
        //setsockopt(get_socket() -> get_sock(), IPPROTO_TCP, TCP)
    #endif
    std::ios_base::sync_with_stdio(HDE::server_config.IO_SYNCHONIZATION);
    HDE::AddressQueue address_queue;
    HDE::ResponderQueue responder_queue;
    std::vector<std::jthread> processes(HDE::server_config.totalUsedThreads);
    //initialize the threads
    for (size_t i = 0; i < HDE::server_config.threadsForAccepter; ++i) {
        processes[i] = std::jthread(&HDE::Server::accepter, this, std::ref(address_queue), logger);
    }
    for (size_t i = 0; i < HDE::server_config.threadsForResponder; ++i) { //1 thread for handler
        processes[i + HDE::server_config.threadsForAccepter] = std::jthread(&HDE::Server::responder, this, std::ref(responder_queue), logger);
    }
    processes[processes.size() - 1] = std::jthread(&HDE::Server::handler, this, std::ref(address_queue), std::ref(responder_queue), logger);
    LOG_INFO(logger, "[Thread {}]: [Main Thread] Threads initialized.", HDE::get_thread_id_cached());
    HDE::serverState.finished_initialization.store(true, std::memory_order_release);
    for (int i = 0; i < processes.size(); ++i) {
        finish_initialization.notify_all();
    }
    LOG_INFO(logger, "[Thread {}]: [Main Thread] Main thread finished executing.", HDE::get_thread_id_cached());
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







//You are about to enter one of the most dangerous territory, my fellow reader; the experimental zone. Any kind of shit can happen


//Do not question the commented








//side dev notes

/*

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

std::string serialized = req.SerializeAsString();
// Send over network...

*/

/*
struct SizeClass {
    size_t size;
    size_t alignment;
    const char* name;
};

constexpr SizeClass SIZE_CLASSES[] = {
    {64, 16, "tiny"},
    {128, 16, "small"},
    {256, 16, "medium"},
    {512, 16, "large"},
    {1024, 16, "xlarge"},
    {2048, 16, "huge"},
    {4096, 16, "massive"}
};
constexpr size_t NUM_SIZE_CLASSES = sizeof(SIZE_CLASSES) / sizeof(SIZE_CLASSES[0]);

class M2HybridAllocator {
private:
    // ===== ARENA COMPONENT (for temporary allocations) =====
    struct Arena {
        char* memory;
        size_t capacity;
        size_t used;
        Arena* next;  // Linked list of arenas
        
        Arena(size_t size) : capacity(size), used(0), next(nullptr) {
            memory = (char*)mmap(
                nullptr, size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0
            );
            
            if (memory == MAP_FAILED) {
                throw std::runtime_error("Arena allocation failed");
            }
            
            // Prefault pages
            for (size_t i = 0; i < size; i += 16384) {
                memory[i] = 0;
            }
        }
        
        ~Arena() {
            munmap(memory, capacity);
        }
        
        void* allocate(size_t size, size_t alignment) {
            // Align pointer
            uintptr_t current = reinterpret_cast<uintptr_t>(memory + used);
            uintptr_t aligned = (current + alignment - 1) & ~(alignment - 1);
            size_t padding = aligned - current;
            
            if (used + padding + size > capacity) {
                return nullptr;  // Arena full
            }
            
            void* ptr = reinterpret_cast<void*>(aligned);
            used += padding + size;
            return ptr;
        }
        
        void reset() {
            used = 0;
            // Optional: advise kernel
            // madvise(memory, capacity, MADV_DONTNEED);
        }
        
        size_t available() const {
            return capacity - used;
        }
    };
    
    // ===== POOL COMPONENT (for fixed-size objects) =====
    template<size_t ObjectSize>
    struct Pool {
        struct alignas(128) Block {
            char storage[ObjectSize];
            std::atomic<Block*> next;
            bool in_use;
            
            // Metadata for debugging
            uint64_t allocation_id;
            const char* alloc_location;
        };
        
        Block* blocks;
        size_t capacity;
        std::atomic<Block*> free_list;
        std::atomic<uint64_t> allocation_counter{0};
        
        // Statistics
        std::atomic<size_t> active_allocations{0};
        std::atomic<size_t> total_allocations{0};
        std::atomic<size_t> peak_allocations{0};
        
        Pool(size_t count) : capacity(count) {
            // Allocate blocks with mmap
            size_t total_size = count * sizeof(Block);
            blocks = (Block*)mmap(
                nullptr, total_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0
            );
            
            if (blocks == MAP_FAILED) {
                throw std::runtime_error("Pool allocation failed");
            }
            
            // Link all blocks
            for (size_t i = 0; i < count - 1; i++) {
                blocks[i].next.store(&blocks[i + 1], std::memory_order_relaxed);
                blocks[i].in_use = false;
                blocks[i].allocation_id = 0;
            }
            blocks[count - 1].next.store(nullptr, std::memory_order_relaxed);
            blocks[count - 1].in_use = false;
            
            free_list.store(&blocks[0], std::memory_order_relaxed);
            
            // Prefault
            for (size_t i = 0; i < count; i += 128) {
                blocks[i].in_use = false;
            }
        }
        
        ~Pool() {
            munmap(blocks, capacity * sizeof(Block));
        }
        
        void* allocate(const char* location = nullptr) {
            Block* block = free_list.load(std::memory_order_relaxed);
            
            while (block != nullptr) {
                Block* next = block->next.load(std::memory_order_relaxed);
                
                if (free_list.compare_exchange_weak(
                    block, next,
                    std::memory_order_acquire,
                    std::memory_order_relaxed))
                {
                    block->in_use = true;
                    block->allocation_id = allocation_counter.fetch_add(1, std::memory_order_relaxed);
                    block->alloc_location = location;
                    
                    // Update statistics
                    size_t active = active_allocations.fetch_add(1, std::memory_order_relaxed) + 1;
                    total_allocations.fetch_add(1, std::memory_order_relaxed);
                    
                    // Update peak
                    size_t current_peak = peak_allocations.load(std::memory_order_relaxed);
                    while (active > current_peak) {
                        if (peak_allocations.compare_exchange_weak(
                            current_peak, active,
                            std::memory_order_relaxed,
                            std::memory_order_relaxed))
                        {
                            break;
                        }
                    }
                    
                    // Prefetch next
                    if (next) {
                        __builtin_prefetch(next, 1, 3);
                    }
                    
                    return block->storage;
                }
                
                __builtin_arm_yield();
            }
            
            return nullptr;  // Pool exhausted
        }
        
        void deallocate(void* ptr) {
            if (!ptr) return;
            
            // Get block from storage pointer
            Block* block = reinterpret_cast<Block*>(
                reinterpret_cast<char*>(ptr) - offsetof(Block, storage)
            );
            
            block->in_use = false;
            active_allocations.fetch_sub(1, std::memory_order_relaxed);
            
            Block* head = free_list.load(std::memory_order_relaxed);
            
            do {
                block->next.store(head, std::memory_order_relaxed);
            } while (!free_list.compare_exchange_weak(
                head, block,
                std::memory_order_release,
                std::memory_order_relaxed
            ));
        }
        
        // Get statistics
        struct Stats {
            size_t capacity;
            size_t active;
            size_t total;
            size_t peak;
            double utilization;
        };
        
        Stats get_stats() const {
            size_t active = active_allocations.load(std::memory_order_relaxed);
            return Stats{
                capacity,
                active,
                total_allocations.load(std::memory_order_relaxed),
                peak_allocations.load(std::memory_order_relaxed),
                (double)active / capacity * 100.0
            };
        }
    };
    
    // ===== HYBRID STATE =====
    
    // Arena for temporary allocations (thread-local)
    static thread_local Arena* current_arena;
    static thread_local Arena* arena_list;  // List of all arenas for this thread
    
    // Pools for each size class (shared across threads)
    Pool<64>* pool_tiny;
    Pool<128>* pool_small;
    Pool<256>* pool_medium;
    Pool<512>* pool_large;
    Pool<1024>* pool_xlarge;
    Pool<2048>* pool_huge;
    Pool<4096>* pool_massive;
    
    // Configuration
    static constexpr size_t ARENA_SIZE = 16 * 1024 * 1024;  // 16MB per arena
    static constexpr size_t POOL_SIZE = 16384;  // 16K objects per pool
    
    // Get size class index
    static size_t get_size_class(size_t size) {
        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            if (size <= SIZE_CLASSES[i].size) {
                return i;
            }
        }
        return SIZE_MAX;  // Too large
    }
    
    // Get pool for size class
    void* allocate_from_pool(size_t class_idx, const char* location) {
        switch (class_idx) {
            case 0: return pool_tiny->allocate(location);
            case 1: return pool_small->allocate(location);
            case 2: return pool_medium->allocate(location);
            case 3: return pool_large->allocate(location);
            case 4: return pool_xlarge->allocate(location);
            case 5: return pool_huge->allocate(location);
            case 6: return pool_massive->allocate(location);
            default: return nullptr;
        }
    }
    
    void deallocate_to_pool(void* ptr, size_t class_idx) {
        switch (class_idx) {
            case 0: pool_tiny->deallocate(ptr); break;
            case 1: pool_small->deallocate(ptr); break;
            case 2: pool_medium->deallocate(ptr); break;
            case 3: pool_large->deallocate(ptr); break;
            case 4: pool_xlarge->deallocate(ptr); break;
            case 5: pool_huge->deallocate(ptr); break;
            case 6: pool_massive->deallocate(ptr); break;
        }
    }
    
    // Allocate new arena for this thread
    Arena* allocate_new_arena() {
        Arena* arena = new Arena(ARENA_SIZE);
        arena->next = arena_list;
        arena_list = arena;
        return arena;
    }
    
public:
    M2HybridAllocator() {
        // Initialize pools
        pool_tiny = new Pool<64>(POOL_SIZE);
        pool_small = new Pool<128>(POOL_SIZE);
        pool_medium = new Pool<256>(POOL_SIZE);
        pool_large = new Pool<512>(POOL_SIZE);
        pool_xlarge = new Pool<1024>(POOL_SIZE);
        pool_huge = new Pool<2048>(POOL_SIZE);
        pool_massive = new Pool<4096>(POOL_SIZE);
    }
    
    ~M2HybridAllocator() {
        // Clean up pools
        delete pool_tiny;
        delete pool_small;
        delete pool_medium;
        delete pool_large;
        delete pool_xlarge;
        delete pool_huge;
        delete pool_massive;
        
        // Clean up arenas (thread-local, so only this thread's)
        Arena* arena = arena_list;
        while (arena) {
            Arena* next = arena->next;
            delete arena;
            arena = next;
        }
    }
    
    // ===== PUBLIC API =====
    
    enum class AllocationType {
        Temporary,  // Use arena (short-lived, freed all at once)
        Persistent  // Use pool (long-lived, freed individually)
    };
    
    // Main allocation function
    void* allocate(size_t size, AllocationType type = AllocationType::Temporary,
                   const char* location = __builtin_FILE()) 
    {
        size_t class_idx = get_size_class(size);
        
        if (type == AllocationType::Persistent && class_idx != SIZE_MAX) {
            // Use pool for fixed-size objects
            return allocate_from_pool(class_idx, location);
        }
        
        // Use arena for temporary or oversized allocations
        if (!current_arena) {
            current_arena = allocate_new_arena();
        }
        
        size_t alignment = (class_idx != SIZE_MAX) ? 
            SIZE_CLASSES[class_idx].alignment : 128;
        
        void* ptr = current_arena->allocate(size, alignment);
        
        if (!ptr) {
            // Current arena full, allocate new one
            current_arena = allocate_new_arena();
            ptr = current_arena->allocate(size, alignment);
        }
        
        return ptr;
    }
    
    // Deallocate (only works for pool allocations)
    void deallocate(void* ptr, size_t size) {
        if (!ptr) return;
        
        size_t class_idx = get_size_class(size);
        
        if (class_idx == SIZE_MAX) {
            // Was allocated from arena or mmap, can't free individually
            return;
        }
        
        deallocate_to_pool(ptr, class_idx);
    }
    
    // Reset arena (frees all temporary allocations)
    void reset_arena() {
        if (current_arena) {
            current_arena->reset();
        }
    }
    
    // Reset all arenas for this thread
    void reset_all_arenas() {
        Arena* arena = arena_list;
        while (arena) {
            arena->reset();
            arena = arena->next;
        }
        current_arena = arena_list;  // Start from first arena
    }
    
    // Get statistics for all pools
    struct PoolStats {
        const char* name;
        size_t size;
        size_t capacity;
        size_t active;
        size_t total;
        size_t peak;
        double utilization;
    };
    
    std::vector<PoolStats> get_pool_statistics() const {
        std::vector<PoolStats> stats;
        
        auto add_stats = [&](auto* pool, size_t idx) {
            auto s = pool->get_stats();
            stats.push_back({
                SIZE_CLASSES[idx].name,
                SIZE_CLASSES[idx].size,
                s.capacity,
                s.active,
                s.total,
                s.peak,
                s.utilization
            });
        };
        
        add_stats(pool_tiny, 0);
        add_stats(pool_small, 1);
        add_stats(pool_medium, 2);
        add_stats(pool_large, 3);
        add_stats(pool_xlarge, 4);
        add_stats(pool_huge, 5);
        add_stats(pool_massive, 6);
        
        return stats;
    }
    
    // Get arena statistics
    struct ArenaStats {
        size_t total_arenas;
        size_t total_capacity;
        size_t total_used;
        double utilization;
    };
    
    ArenaStats get_arena_statistics() const {
        size_t count = 0;
        size_t capacity = 0;
        size_t used = 0;
        
        Arena* arena = arena_list;
        while (arena) {
            count++;
            capacity += arena->capacity;
            used += arena->used;
            arena = arena->next;
        }
        
        return ArenaStats{
            count,
            capacity,
            used,
            capacity > 0 ? (double)used / capacity * 100.0 : 0.0
        };
    }
    
    // Print statistics
    void print_statistics() const {
        std::cout << "\n=== HYBRID ALLOCATOR STATISTICS ===\n";
        
        // Pool stats
        std::cout << "\nPOOL STATISTICS:\n";
        std::cout << "Size    | Name     | Capacity | Active | Total   | Peak   | Util%\n";
        std::cout << "--------|----------|----------|--------|---------|--------|-------\n";
        
        for (const auto& stat : get_pool_statistics()) {
            printf("%-7zu | %-8s | %8zu | %6zu | %7zu | %6zu | %5.1f%%\n",
                   stat.size, stat.name, stat.capacity, stat.active,
                   stat.total, stat.peak, stat.utilization);
        }
        
        // Arena stats
        std::cout << "\nARENA STATISTICS:\n";
        auto arena_stats = get_arena_statistics();
        printf("Total Arenas: %zu\n", arena_stats.total_arenas);
        printf("Total Capacity: %zu bytes (%.2f MB)\n", 
               arena_stats.total_capacity,
               arena_stats.total_capacity / (1024.0 * 1024.0));
        printf("Total Used: %zu bytes (%.2f MB)\n",
               arena_stats.total_used,
               arena_stats.total_used / (1024.0 * 1024.0));
        printf("Utilization: %.1f%%\n", arena_stats.utilization);
        
        std::cout << "\n===================================\n";
    }
};

// Define thread-local storage
thread_local M2HybridAllocator::Arena* M2HybridAllocator::current_arena = nullptr;
thread_local M2HybridAllocator::Arena* M2HybridAllocator::arena_list = nullptr;

class AllocationTelemetry {
private:
    struct AllocationRecord {
        const char* location;      // __FILE__
        size_t size;
        size_t alignment;
        uint64_t timestamp_ns;
        uint64_t thread_id;
        bool from_pool;
        
        // Performance metrics
        uint64_t allocation_time_ns;
    };
    
    struct LocationStats {
        const char* location;
        size_t total_allocations;
        size_t total_bytes;
        size_t min_size;
        size_t max_size;
        double avg_size;
        uint64_t total_time_ns;
        double avg_time_ns;
        
        // Allocation pattern
        std::unordered_map<size_t, size_t> size_histogram;
    };
    
    // Ring buffer for recent allocations
    static constexpr size_t RING_BUFFER_SIZE = 65536;
    AllocationRecord ring_buffer[RING_BUFFER_SIZE];
    std::atomic<size_t> ring_buffer_head{0};
    
    // Per-location statistics
    std::unordered_map<const char*, LocationStats> location_stats;
    mutable std::mutex stats_mutex;
    
    // Global counters (lock-free)
    std::atomic<uint64_t> total_allocations{0};
    std::atomic<uint64_t> total_bytes_allocated{0};
    std::atomic<uint64_t> total_allocation_time_ns{0};
    
    // Per-thread counters
    struct alignas(128) ThreadStats {
        uint64_t allocations;
        uint64_t bytes;
        uint64_t time_ns;
        char padding[128 - 3 * sizeof(uint64_t)];
    };
    
    static constexpr size_t MAX_THREADS = 32;
    ThreadStats thread_stats[MAX_THREADS];
    std::atomic<size_t> thread_count{0};
    
    // Get thread-local index
    static size_t get_thread_index() {
        thread_local size_t index = SIZE_MAX;
        
        if (index == SIZE_MAX) {
            // First time this thread is seen, assign an index
            // This is simplified; real implementation would use pthread_getspecific
            static std::atomic<size_t> next_index{0};
            index = next_index.fetch_add(1, std::memory_order_relaxed);
        }
        
        return index;
    }
    
    // Get current timestamp
    static uint64_t get_timestamp_ns() {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()
        ).count();
    }
    
    // Get thread ID
    static uint64_t get_thread_id() {
        std::hash<std::thread::id> hasher;
        return hasher(std::this_thread::get_id());
    }
    
public:
    AllocationTelemetry() {
        for (size_t i = 0; i < MAX_THREADS; i++) {
            thread_stats[i].allocations = 0;
            thread_stats[i].bytes = 0;
            thread_stats[i].time_ns = 0;
        }
    }
    
    // Record an allocation
    void record_allocation(const char* location, size_t size, size_t alignment,
                          bool from_pool, uint64_t allocation_time_ns) 
    {
        uint64_t timestamp = get_timestamp_ns();
        uint64_t thread_id = get_thread_id();
        size_t thread_idx = get_thread_index();
        
        // Update global counters (lock-free)
        total_allocations.fetch_add(1, std::memory_order_relaxed);
        total_bytes_allocated.fetch_add(size, std::memory_order_relaxed);
        total_allocation_time_ns.fetch_add(allocation_time_ns, std::memory_order_relaxed);
        
        // Update thread-local counters
        if (thread_idx < MAX_THREADS) {
            thread_stats[thread_idx].allocations++;
            thread_stats[thread_idx].bytes += size;
            thread_stats[thread_idx].time_ns += allocation_time_ns;
        }
        
        // Add to ring buffer
        size_t head = ring_buffer_head.fetch_add(1, std::memory_order_relaxed);
        size_t index = head % RING_BUFFER_SIZE;
        
        ring_buffer[index] = AllocationRecord{
            location,
            size,
            alignment,
            timestamp,
            thread_id,
            from_pool,
            allocation_time_ns
        };
        
        // Update location statistics (with lock)
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            
            auto& stats = location_stats[location];
            
            if (stats.total_allocations == 0) {
                // First allocation at this location
                stats.location = location;
                stats.min_size = size;
                stats.max_size = size;
            }
            
            stats.total_allocations++;
            stats.total_bytes += size;
            stats.min_size = std::min(stats.min_size, size);
            stats.max_size = std::max(stats.max_size, size);
            stats.avg_size = (double)stats.total_bytes / stats.total_allocations;
            stats.total_time_ns += allocation_time_ns;
            stats.avg_time_ns = (double)stats.total_time_ns / stats.total_allocations;
            
            // Update histogram
            stats.size_histogram[size]++;
        }
    }
    
    // Get snapshot of current statistics
    struct GlobalStats {
        uint64_t total_allocations;
        uint64_t total_bytes;
        double avg_allocation_size;
        uint64_t total_time_ns;
        double avg_allocation_time_ns;
        size_t active_threads;
    };
    
    GlobalStats get_global_stats() const {
        uint64_t allocs = total_allocations.load(std::memory_order_relaxed);
        uint64_t bytes = total_bytes_allocated.load(std::memory_order_relaxed);
        uint64_t time_ns = total_allocation_time_ns.load(std::memory_order_relaxed);
        
        return GlobalStats{
            allocs,
            bytes,
            allocs > 0 ? (double)bytes / allocs : 0.0,
            time_ns,
            allocs > 0 ? (double)time_ns / allocs : 0.0,
            thread_count.load(std::memory_order_relaxed)
        };
    }
    
    // Get top N hotspots (locations with most allocations)
    std::vector<LocationStats> get_top_hotspots(size_t n) const {
        std::lock_guard<std::mutex> lock(stats_mutex);
        
        std::vector<LocationStats> stats;
        stats.reserve(location_stats.size());
        
        for (const auto& pair : location_stats) {
            stats.push_back(pair.second);
        }
        
        // Sort by total allocations (descending)
        std::sort(stats.begin(), stats.end(), 
            [](const LocationStats& a, const LocationStats& b) {
                return a.total_allocations > b.total_allocations;
            });
        
        if (stats.size() > n) {
            stats.resize(n);
        }
        
        return stats;
    }
    
    // Analyze allocation patterns
    struct AllocationPattern {
        double temporal_locality;    // How clustered in time
        double spatial_locality;     // How similar sizes are
        double thread_affinity;      // How much one thread dominates
        size_t dominant_size;        // Most common allocation size
        double size_variance;        // How varied sizes are
    };
    
    AllocationPattern analyze_pattern(const char* location) const {
        std::lock_guard<std::mutex> lock(stats_mutex);
        
        auto it = location_stats.find(location);
        if (it == location_stats.end()) {
            return AllocationPattern{0, 0, 0, 0, 0};
        }
        
        const auto& stats = it->second;
        
        // Find dominant size
        size_t dominant_size = 0;
        size_t max_count = 0;
        
        for (const auto& pair : stats.size_histogram) {
            if (pair.second > max_count) {
                max_count = pair.second;
                dominant_size = pair.first;
            }
        }
        
        // Calculate spatial locality (how concentrated sizes are)
        double spatial = max_count / (double)stats.total_allocations;
        
        // Calculate size variance
        double variance = 0.0;
        for (const auto& pair : stats.size_histogram) {
            double diff = (double)pair.first - stats.avg_size;
            variance += diff * diff * pair.second;
        }
        variance /= stats.total_allocations;
        
        return AllocationPattern{
            0.0,  // temporal would require timestamp analysis
            spatial,
            0.0,  // thread affinity would require thread tracking
            dominant_size,
            variance
        };
    }
    
    // Export statistics to JSON
    void export_to_json(const std::string& filename) const {
        std::ofstream file(filename);
        
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return;
        }
        
        auto global = get_global_stats();
        
        file << "{\n";
        file << "  \"global\": {\n";
        file << "    \"total_allocations\": " << global.total_allocations << ",\n";
        file << "    \"total_bytes\": " << global.total_bytes << ",\n";
        file << "    \"avg_allocation_size\": " << global.avg_allocation_size << ",\n";
        file << "    \"total_time_ns\": " << global.total_time_ns << ",\n";
        file << "    \"avg_allocation_time_ns\": " << global.avg_allocation_time_ns << ",\n";
        file << "    \"active_threads\": " << global.active_threads << "\n";
        file << "  },\n";
        
        // Thread statistics
        file << "  \"threads\": [\n";
        for (size_t i = 0; i < MAX_THREADS; i++) {
            if (thread_stats[i].allocations > 0) {
                if (i > 0) file << ",\n";
                file << "    {\n";
                file << "      \"thread_index\": " << i << ",\n";
                file << "      \"allocations\": " << thread_stats[i].allocations << ",\n";
                file << "      \"bytes\": " << thread_stats[i].bytes << ",\n";
                file << "      \"time_ns\": " << thread_stats[i].time_ns << "\n";
                file << "    }";
            }
        }
        file << "\n  ],\n";
        
        // Location hotspots
        file << "  \"hotspots\": [\n";
        auto hotspots = get_top_hotspots(20);
        for (size_t i = 0; i < hotspots.size(); i++) {
            if (i > 0) file << ",\n";
            const auto& stats = hotspots[i];
            
            file << "    {\n";
            file << "      \"location\": \"" << stats.location << "\",\n";
            file << "      \"total_allocations\": " << stats.total_allocations << ",\n";
            file << "      \"total_bytes\": " << stats.total_bytes << ",\n";
            file << "      \"min_size\": " << stats.min_size << ",\n";
            file << "      \"max_size\": " << stats.max_size << ",\n";
            file << "      \"avg_size\": " << stats.avg_size << ",\n";
            file << "      \"avg_time_ns\": " << stats.avg_time_ns << ",\n";
            
            // Size histogram
            file << "      \"size_histogram\": {\n";
            bool first = true;
            for (const auto& pair : stats.size_histogram) {
                if (!first) file << ",\n";
                file << "        \"" << pair.first << "\": " << pair.second;
                first = false;
            }
            file << "\n      }\n";
            file << "    }";
        }
        file << "\n  ],\n";
        
        // Recent allocations (last 100)
        file << "  \"recent_allocations\": [\n";
        size_t head = ring_buffer_head.load(std::memory_order_relaxed);
        size_t count = std::min((size_t)100, std::min(head, RING_BUFFER_SIZE));
        
        for (size_t i = 0; i < count; i++) {
            if (i > 0) file << ",\n";
            size_t idx = (head - count + i) % RING_BUFFER_SIZE;
            const auto& rec = ring_buffer[idx];
            
            file << "    {\n";
            file << "      \"location\": \"" << rec.location << "\",\n";
            file << "      \"size\": " << rec.size << ",\n";
            file << "      \"alignment\": " << rec.alignment << ",\n";
            file << "      \"timestamp_ns\": " << rec.timestamp_ns << ",\n";
            file << "      \"thread_id\": " << rec.thread_id << ",\n";
            file << "      \"from_pool\": " << (rec.from_pool ? "true" : "false") << ",\n";
            file << "      \"allocation_time_ns\": " << rec.allocation_time_ns << "\n";
            file << "    }";
        }
        file << "\n  ]\n";
        
        file << "}\n";
        
        file.close();
        std::cout << "Telemetry exported to: " << filename << std::endl;
    }
    
    // Print human-readable report
    void print_report() const {
        auto global = get_global_stats();
        
        std::cout << "\n╔════════════════════════════════════════════════════════╗\n";
        std::cout << "║               ALLOCATION TELEMETRY REPORT              ║\n";
        std::cout << "╚════════════════════════════════════════════════════════╝\n\n";
        
        // Global stats
        std::cout << "GLOBAL STATISTICS:\n";
        std::cout << "  Total Allocations:  " << global.total_allocations << "\n";
        std::cout << "  Total Bytes:        " << global.total_bytes 
                  << " (" << (global.total_bytes / 1024.0 / 1024.0) << " MB)\n";
        std::cout << "  Avg Allocation:     " << global.avg_allocation_size << " bytes\n";
        std::cout << "  Total Time:         " << global.total_time_ns << " ns\n";
        std::cout << "  Avg Time/Alloc:     " << global.avg_allocation_time_ns << " ns\n";
        std::cout << "  Active Threads:     " << global.active_threads << "\n\n";
        
        // Thread stats
        std::cout << "THREAD STATISTICS:\n";
        std::cout << "  Thread | Allocations | Bytes      | Avg Time (ns)\n";
        std::cout << "  -------|-------------|------------|---------------\n";
        for (size_t i = 0; i < MAX_THREADS; i++) {
            if (thread_stats[i].allocations > 0) {
                printf("  %6zu | %11lu | %10lu | %13.1f\n",
                       i,
                       thread_stats[i].allocations,
                       thread_stats[i].bytes,
                       thread_stats[i].allocations > 0 ? 
                           (double)thread_stats[i].time_ns / thread_stats[i].allocations : 0.0);
            }
        }
        
        // Top hotspots
        std::cout << "\nTOP 10 ALLOCATION HOTSPOTS:\n";
        std::cout << "  Location                          | Count    | Total Bytes | Avg Size | Avg Time (ns)\n";
        std::cout << "  ----------------------------------|----------|-------------|----------|---------------\n";
        
        auto hotspots = get_top_hotspots(10);
        for (const auto& stats : hotspots) {
            printf("  %-33s | %8zu | %11zu | %8.0f | %13.1f\n",
                   stats.location,
                   stats.total_allocations,
                   stats.total_bytes,
                   stats.avg_size,
                   stats.avg_time_ns);
        }
        
        // Allocation patterns
        std::cout << "\nALLOCATION PATTERNS:\n";
        for (const auto& stats : hotspots) {
            auto pattern = analyze_pattern(stats.location);
            
            std::cout << "\n  " << stats.location << ":\n";
            std::cout << "    Spatial Locality: " << (pattern.spatial_locality * 100.0) << "%\n";
            std::cout << "    Dominant Size:    " << pattern.dominant_size << " bytes\n";
            std::cout << "    Size Variance:    " << pattern.size_variance << "\n";
            
            // Recommendation
            if (pattern.spatial_locality > 0.8) {
                std::cout << "    RECOMMENDATION: Use object pool (size is consistent)\n";
            } else if (pattern.size_variance < 100) {
                std::cout << "    RECOMMENDATION: Use small size classes\n";
            } else {
                std::cout << "    RECOMMENDATION: Use arena allocator\n";
            }
        }
        
        std::cout << "\n════════════════════════════════════════════════════════\n\n";
    }
    
    // Real-time monitoring (print every N seconds)
    void start_monitoring(int interval_seconds) {
        std::thread monitor_thread([this, interval_seconds]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
                this->print_report();
            }
        });
        
        monitor_thread.detach();
    }
};

class M2HybridAllocatorWithTelemetry : public M2HybridAllocator {
private:
    AllocationTelemetry telemetry;
    bool telemetry_enabled;
    
public:
    M2HybridAllocatorWithTelemetry(bool enable_telemetry = true)
        : telemetry_enabled(enable_telemetry) {}
    
    void* allocate(size_t size, AllocationType type = AllocationType::Temporary,
                   const char* location = __builtin_FILE()) 
    {
        uint64_t start_time = 0;
        
        if (telemetry_enabled) {
            start_time = std::chrono::high_resolution_clock::now()
                .time_since_epoch().count();
        }
        
        // Perform allocation
        void* ptr = M2HybridAllocator::allocate(size, type, location);
        
        if (telemetry_enabled && ptr) {
            uint64_t end_time = std::chrono::high_resolution_clock::now()
                .time_since_epoch().count();
            uint64_t duration = end_time - start_time;
            
            telemetry.record_allocation(
                location,
                size,
                128,  // Default alignment
                type == AllocationType::Persistent,
                duration
            );
        }
        
        return ptr;
    }
    
    AllocationTelemetry& get_telemetry() {
        return telemetry;
    }
    
    void enable_telemetry(bool enable) {
        telemetry_enabled = enable;
    }
};

// Global allocator with telemetry
M2HybridAllocatorWithTelemetry global_allocator(true);

void benchmark_allocator() {
    // Start real-time monitoring (prints report every 5 seconds)
    global_allocator.get_telemetry().start_monitoring(5);
    
    // Your server code runs...
    
    // After some time, print final report
    global_allocator.get_telemetry().print_report();
    
    // Export to JSON for analysis
    global_allocator.get_telemetry().export_to_json("allocation_stats.json");
}

void Server::handler_with_telemetry(quill::Logger* logger) {
    for (;;) {
        // Allocations are automatically tracked!
        char* buffer = (char*)global_allocator.allocate(
            1024,
            M2HybridAllocator::AllocationType::Temporary,
            __FILE__ ":" __LINE__  // Track exact location
        );
        
        // Use buffer...
        
        global_allocator.reset_arena();
    }
}

template<typename T>
class M2STLAllocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using size_type = size_t;
    using difference_type = ptrdiff_t;
    
    // Required typedef for rebind
    template<typename U>
    struct rebind {
        using other = M2STLAllocator<U>;
    };
    
private:
    M2HybridAllocator* allocator_;
    M2HybridAllocator::AllocationType type_;
    
public:
    M2STLAllocator(M2HybridAllocator* alloc = nullptr,
                   M2HybridAllocator::AllocationType type = 
                       M2HybridAllocator::AllocationType::Temporary)
        : allocator_(alloc ? alloc : &global_allocator), type_(type) {}
    
    // Copy constructor
    M2STLAllocator(const M2STLAllocator& other)
        : allocator_(other.allocator_), type_(other.type_) {}
    
    // Rebind constructor
    template<typename U>
    M2STLAllocator(const M2STLAllocator<U>& other)
        : allocator_(other.get_allocator()), type_(other.get_type()) {}
    
    // Allocate
    T* allocate(size_t n) {
        if (n == 0) return nullptr;
        
        size_t size = n * sizeof(T);
        void* ptr = allocator_->allocate(size, type_);
        
        if (!ptr) {
            throw std::bad_alloc();
        }
        
        return static_cast<T*>(ptr);
    }
    
    // Deallocate
    void deallocate(T* ptr, size_t n) {
        if (!ptr) return;
        
        if (type_ == M2HybridAllocator::AllocationType::Persistent) {
            allocator_->deallocate(ptr, n * sizeof(T));
        }
        // If Temporary, arena will handle cleanup
    }
    
    // Construct object
    template<typename U, typename... Args>
    void construct(U* ptr, Args&&... args) {
        new (ptr) U(std::forward<Args>(args)...);
    }
    
    // Destroy object
    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
    
    // Comparison operators (required)
    bool operator==(const M2STLAllocator& other) const {
        return allocator_ == other.allocator_ && type_ == other.type_;
    }
    
    bool operator!=(const M2STLAllocator& other) const {
        return !(*this == other);
    }
    
    // Accessors for rebind
    M2HybridAllocator* get_allocator() const { return allocator_; }
    M2HybridAllocator::AllocationType get_type() const { return type_; }
};

// Type aliases for convenience
template<typename T>
using M2Vector = std::vector<T, M2STLAllocator<T>>;

using M2String = std::basic_string<char, std::char_traits<char>, M2STLAllocator<char>>;

template<typename K, typename V>
using M2Map = std::map<K, V, std::less<K>, 
    M2STLAllocator<std::pair<const K, V>>>;

template<typename K, typename V>
using M2UnorderedMap = std::unordered_map<K, V, std::hash<K>, std::equal_to<K>,
    M2STLAllocator<std::pair<const K, V>>>;

class SlabAllocator {
    struct Slab {
        void* memory;          // Base pointer
        size_t object_size;    // Size of objects in this slab
        size_t capacity;       // Number of objects
        FreeList* free_list;   // Available objects
        Slab* next;            // Next slab (if this one fills)
    };
    
    // One slab per size class
    Slab* slabs[NUM_SIZE_CLASSES];
    
    void* allocate(size_t size) {
        // 1. Find size class
        size_t class_idx = get_size_class(size);
        
        // 2. Get slab for this size
        Slab* slab = slabs[class_idx];
        
        // 3. Pop from slab's free list
        if (slab->free_list) {
            return pop_from_free_list(slab);
        }
        
        // 4. If slab full, allocate new slab
        slab->next = allocate_new_slab(size_class);
        return allocate_from(slab->next);
    }
};
*/