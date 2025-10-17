#include "Server.hpp"
#include <iostream>
#include <pthread.h>
#include <sched.h>
//dev notes
/*Resources:
https://www.geeksforgeeks.org/cpp/multithreading-in-cpp/
https://www.geeksforgeeks.org/cpp/queue-cpp-stl/
http://geeksforgeeks.org/cpp/vectoremplace_back-c-stl/
*/
//Developed for C++23.
//remember to catch std::overflow_error, std::runtime_error, std::exception, and other C++ specific errors before catch(...).
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




//try to prefer lock_guard over unique_lock



/*
 * LOCK HIERARCHY (always acquire in this order):
 * 1. console_mutex
 * 2. rate_limited_mutex  
 * 3. address_queue_mutex
 * 4. responder_queue_mutex
 * 5. file_access_mutex
 * 
 * Never acquire a higher-priority lock while holding a lower one!
 */




//All getter/setter functions are only interacting with one object; the main AddressQueue/ResponderQueue object, so have lock_guard's or unique_lock's.
//in the future, if possible create a struct for each of these mutexes/conditional variables and add padding; but only do it for frequently-accessed ones.
//definitions
alignas(CACHE_LINE_SIZE) std::mutex address_queue_mutex;
alignas(CACHE_LINE_SIZE) std::mutex responder_queue_mutex;
alignas(CACHE_LINE_SIZE) std::mutex r_e_m_mutex;
alignas(CACHE_LINE_SIZE) std::mutex console_mutex;
alignas(CACHE_LINE_SIZE) std::mutex clean_up_mutex;
alignas(CACHE_LINE_SIZE) std::mutex general_mutex;
alignas(CACHE_LINE_SIZE) std::mutex file_access_mutex; //to account for fstream's thread-risky nature
alignas(CACHE_LINE_SIZE) std::mutex rate_limited_mutex;
alignas(CACHE_LINE_SIZE) std::condition_variable finish_initialization;
alignas(CACHE_LINE_SIZE) std::condition_variable addr_in_addr_queue;
alignas(CACHE_LINE_SIZE) std::condition_variable resp_in_res_queue;
alignas(CACHE_LINE_SIZE) std::atomic<bool> finished_initialization;
alignas(CACHE_LINE_SIZE) std::atomic<bool> stop_server = false;
std::unordered_map<std::string, std::list<std::chrono::steady_clock::time_point>> HDE::connection_history;

//debugging
alignas(CACHE_LINE_SIZE) const bool debugging_checkpoints = false;


//for future attempts:     [Thread <thread id>]: [<timestamp>]: [<processing component, if possible>] [<message>]


//Main code, do not modify
//Utilities
//Get the current time in a string
//NOT-Thread-safe
inline std::string HDE::get_current_time() {
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm local_tm_struct;
    if (localtime_r(&now_c, &local_tm_struct) == nullptr) [[unlikely]] {
        // Handle error, return empty string or default time
        return "TimeError"; 
    }
    std::ostringstream oss;
    oss << std::put_time(&local_tm_struct, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}
//NOT-Thread safe
inline void HDE::Server::logClientInfo(const std::string_view processing_component, const std::string_view message) const {
    if (!message.empty()) [[likely]] {
        std::cout << std::format("[Thread {}]: [{}]: [{}] logClientInfo(): {}\n", std::this_thread::get_id(), HDE::get_current_time(), processing_component, message);
    } else [[unlikely]] {
        std::cout << std::format("[Thread {}]: [{}]: [{}] logClientInfo(): <empty>\n", std::this_thread::get_id(), HDE::get_current_time(), processing_component);
    }
}
//Function retrieve error from the global variable errno.
//This is assuming the user had locked the console writing permissions using std::mutex console_mutex before use and unlocks it right after execution.
//NOT Thread-safe, need to acquire console_mutex
inline void HDE::reportErrorMessage() {
    int error_code = errno;
    std::cout << std::format("[Thread {}]: [{}]: An error has occured (Description, if any, line above).\n", std::this_thread::get_id(), HDE::get_current_time());
    if (errno == EINTR) [[unlikely]] {
        std::cout << std::format("[Thread {}]: [{}]: Message: A possible interrupted system call is detected.\n", std::this_thread::get_id(), HDE::get_current_time());
    } else if (errno == EMFILE || errno == ENFILE) [[unlikely]] {
        std::cout << std::format("[Thread {}]: [{}]: Message: The server is using a lot of resources (Too many open files). Check immediately.\n", std::this_thread::get_id(), HDE::get_current_time());
    } else [[likely]] {
        std::cout << std::format("[Thread {}]: [{}]: Message: <nothing, i was too lazy to put anything>.\n", std::this_thread::get_id(), HDE::get_current_time());
    }
}
//NOT Thread-safe, need to acquire address_queue_mutex before execution
//LOCK console_mutex BEFORE CALLING FUNCTION
void HDE::AddressQueue::emplace_response(int loc, std::span<const char> data) {
    if (address_queue.size() < HDE::max_incoming_address_queue_size) [[likely]] {
        address_queue.emplace(loc, std::string(data.data(), data.size()));
        addr_in_addr_queue.notify_one();
    } else [[unlikely]] {
        std::cout << std::format("[Thread {}]: [{}]: Rejecting client due to incoming_address_queue_size overflow. Overflow limit: {} clients.\n", std::this_thread::get_id(), HDE::get_current_time(), std::to_string(HDE::max_incoming_address_queue_size));
    }
}
//NOT Thread-safe, need to acquire address_queue_mutex before execution
//LOCK console_mutex BEFORE calling function
void HDE::AddressQueue::emplace_response(const int location, const std::string_view msg) {
    if (address_queue.size() < HDE::max_incoming_address_queue_size) [[likely]] {
        address_queuel.emplace(location, msg);
        addr_in_addr_queue.notify_one();
    } else [[unlikely]] {
        std::cout << std::format("[Thread {}]: [{}]: Rejecting client due to incoming_address_queue_size overflow. Overflow limit: {} clients.\n", std::this_thread::get_id(), HDE::get_current_time(), std::to_string(HDE::max_incoming_address_queue_size));
    }
}
//NOT Thread-safe, need to acquire address_queue_mutex before execution
//VS Code might tell you there's an error here, but trust me there's none, just left-click and hover over the variable and it is gone.
struct Request HDE::AddressQueue::get_response() {
    if (!address_queue.empty()) [[likely]] {
        struct Request res = std::move(address_queue.front());
        address_queue.pop();
        return std::move(res);
    } else [[unlikely]] {
        return Request{};
    }
}
//NOT Thread-safe, need to acquire address_queue_mutex before execution
int HDE::AddressQueue::get_size() const noexcept {
    return address_queue.size();
}
//Thread-safe
void HDE::AddressQueue::closeAllConnections() {
    std::vector<int> fds_to_close;
    {
        std::lock_guard<std::mutex> lock(address_queue_mutex);
        while (!address_queue.empty()) {
            if (address_queue.front().location != -1) [[likely]] {
                fds_to_close.push_back(address_queue.front().location);
            }
            address_queue.pop();
        }
    }
    for (int fd : fds_to_close) {
        try {
            close(fd);
        } catch (...) {
            shutdown(fd, SHUT_RDWR);
        }
    }
}
//Thread-safe, alternate version for the closeAllConnections(), only recommended for 1000+ concurrent connections
/*void HDE::AddressQueue::closeAllConnections() noexcept(false) {
    std::vector<int> fds_to_close;
    {
        std::lock_guard<std::mutex> lock(address_queue_mutex);
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
//NOT Thread-safe
bool HDE::AddressQueue::empty() const noexcept {
    return address_queue.empty();
}
//will not add element if adding them means allResponses's size exceeds HDE::maxResponsesQueue.
//in the future if the website grows might switch [[likely]] with [[unlikely]]
//NOT Thread-safe, need to acquire responder_queue_mutex
void HDE::ResponderQueue::emplace_response(int loc, std::span<const char> data) noexcept {
    if (allResponses.size() <= HDE::max_responses_queue_size) [[likely]] {
        allResponses.emplace(loc, std::string(data.data(), data.size()));
        resp_in_res_queue.notify_one();
    } else [[unlikely]] {
        std::cout << std::format("[Thread {}]: [{}]: Rejecting client due to max_responses_queue_size overflow; Overflow limit: {} clients.\n", std::this_thread::get_id(), HDE::get_current_time(), std::to_string(HDE::max_responses_queue_size));
    }
}
//NOT Thread-safe, need to acquire responder_queue_mutex
//Optimize the passing of parameter msg.
void HDE::ResponderQueue::emplace_response(const int destination, const std::string_view msg) {
    if (allResponses.size() <= HDE::max_responses_queue_size) [[likely]] {
        allResponses.emplace(destination, msg);
        resp_in_res_queue.notify_one();
    } else [[unlikely]] {
        std::cout << std::format("[Thread {}]: [{}]: Rejecting client due to max_responses_queue_size overflow; Overflow limit: {} clients.\n", std::this_thread::get_id(), HDE::get_current_time(), std::to_string(HDE::max_responses_queue_size));
    }
}
//NOT Thread-safe, need to acquire responder_queue_mutex
struct Response HDE::ResponderQueue::get_response() noexcept {
    if (!allResponses.empty()) [[likely]] {
        struct Response destination = std::move(allResponses.front());
        allResponses.pop();
        return destination;
    } else [[unlikely]] {
        return Response{};
    }
}
//NOT Thread-safe, need to acquire responder_queue_mutex
int HDE::ResponderQueue::get_size() const noexcept {
    return allResponses.size();
}
//Thread-safe
void HDE::ResponderQueue::closeAllConnections() {
    std::vector<int> fds_to_close;
    {
        std::lock_guard<std::mutex> lock(responder_queue_mutex);
        while (!allResponses.empty()) {
            if (allResponses.front().destination != -1) [[likely]] {
                fds_to_close.push_back(allResponses.front().destination);
            }
            allResponses.pop();
        }
    }
    for (int fd : fds_to_close) {
        try {
            close(fd);
        } catch (...) {
            shutdown(fd, SHUT_RDWR);
        }
    }
}
//Thread-safe, alternate version for the closeAllConnections(), only recommended for 1000+ concurrent connections
/*void HDE::AddressQueue::closeAllConnections() noexcept(false) {
    std::vector<int> fds_to_close;
    {
        std::lock_guard<std::mutex> lock(responder_queue_mutex);
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
//NOT Thread-safe
bool HDE::ResponderQueue::empty() const noexcept {
    return allResponses.empty();
}

//Constructor
HDE::Server::Server() : SimpleServer(AF_INET, SOCK_STREAM, 0, HDE::Port, INADDR_ANY, HDE::queueCount) {
    load_cache();
    launch();
}

//NOT Thread-safe, lock via file_access_mutex
void HDE::Server::load_cache()  {
    //load other file caches here
    std::fstream inputFile(html_file_path);
    if (!inputFile.is_open()) [[unlikely]] {
        std::cerr << std::format("FATAL: Cannot open file: {}\n", html_file_path);
        exit(EXIT_FAILURE);
    }
    std::string line;
    while (std::getline(inputFile, line)) {
        main_page_template_cache += (line + "\n");
    }
    if (main_page_template_cache.empty()) [[unlikely]] {
        std::cerr << "FATAL: Template cache is empty!\n";
        exit(EXIT_FAILURE);
    }
    size_t content_length = main_page_template_cache.length();
    //this rvalue reference will most likely crash.
    std::string &&headers = std::format(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "\r\n",
        content_length
    );
    main_page_template_cache.insert(0, headers);
    inputFile.close();
    main_page_template_cache_size = main_page_template_cache.length();
    std::cout << std::format("Template cache loaded: {} bytes\n", main_page_template_cache.size());
}

void HDE::clean_server_shutdown(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue) {
    stop_server.store(true, std::memory_order_seq_cst);
    std::lock_guard<std::mutex> lock(console_mutex);
    address_queue.closeAllConnections();
    responder_queue.closeAllConnections();
    resp_in_res_queue.notify_all();
    addr_in_addr_queue.notify_all();
}
//Now finnally Thread-safe, uses rate_limited_mutex.
bool HDE::is_rate_limited(const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(rate_limited_mutex);
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    std::list<std::chrono::steady_clock::time_point>& times = HDE::connection_history[client_ip];
    times.remove_if([&now](const std::chrono::steady_clock::time_point& tp) {
        return now - tp > std::chrono::seconds(1);
    });
    if (times.size() >= HDE::MAX_CONNECTIONS_PER_SECOND) [[unlikely]] {
        return true;
    }
    times.push_back(now);
    return false;
}
//Runs on independent thread
void HDE::Server::accepter(HDE::AddressQueue& address_queue) {
    std::unique_lock<std::mutex> init_lock(console_mutex);
    std::unique_lock<std::mutex> addr_lock(address_queue_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [finished_initialization_ptr = &finished_initialization] { return finished_initialization_ptr -> load(); });
    std::cout << std::format("[Thread: {}]: [{}]: [Accepter] Initializing...\n", std::this_thread::get_id(), HDE::get_current_time());
    init_lock.unlock();
    for (;;) {
        if (stop_server.load(std::memory_order_seq_cst)) [[unlikely]] {
            break;
        }
        char local_buf[sizeof(buffer)];
        constexpr size_t buf_size = sizeof(buffer);
        init_lock.lock();
        std::cout << std::format("[Thread: {}]: [{}]: [Accepter] Waiting for requests...\n", std::this_thread::get_id(), HDE::get_current_time());
        init_lock.unlock();
        struct sockaddr_in address = get_socket() -> get_address();
        int addrlen = sizeof(address);
        int client_socket_fd = accept(get_socket() -> get_sock(), reinterpret_cast<struct sockaddr*>(&address), reinterpret_cast<socklen_t*>(&addrlen));
        if (debugging_checkpoints) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] Checkpoint 1 reached.\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        if (client_socket_fd < 0) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] Initializing...\n", std::this_thread::get_id(), HDE::get_current_time());
            HDE::reportErrorMessage();
            continue;
        }
        if (debugging_checkpoints) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] Checkpoint 2 reached\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        const size_t MAX_PACKET_SIZE = sizeof(buffer) - 1;
        char ip_str[INET6_ADDRSTRLEN];
        int res = getnameinfo(reinterpret_cast<struct sockaddr*>(&address), sizeof(address), ip_str, INET6_ADDRSTRLEN, nullptr, 0, NI_NUMERICHOST);
        if (res != 0) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] A client has an unknown IP address. The server will attempt to close the connection; and shuts it down if that fails.\n", std::this_thread::get_id(), HDE::get_current_time());
            HDE::reportErrorMessage();
            try {
                close(client_socket_fd);
            } catch (const std::runtime_error& error) {
                std::cout << std::format("[Thread: {}]: [{}]: [Accepter] An error occured when trying to close a client connection. Force closing...\n", std::this_thread::get_id(), HDE::get_current_time());
                std::cout << std::format("[Thread: {}]: [{}]: [Accepter] [Runtime Error] More details: {}\n", std::this_thread::get_id(), HDE::get_current_time(), error.what());
                HDE::reportErrorMessage();
                HDE::Server::logClientInfo("Accepter", ip_str);
                shutdown(client_socket_fd, SHUT_RDWR);
            } catch(const std::exception& error) {
                std::cout << std::format("[Thread: {}]: [{}]: [Accepter] An error occured when trying to close a client connection.\n", std::this_thread::get_id(), HDE::get_current_time());
                std::cout << std::format("[Thread: {}]: [{}]: [Accepter] [Standard Exception] More details: {}\n", std::this_thread::get_id(), HDE::get_current_time(), error.what());
                HDE::reportErrorMessage();
                HDE::Server::logClientInfo("Accepter", ip_str);
                shutdown(client_socket_fd, SHUT_RDWR);
            } catch (...) {
                std::cout << std::format("[Thread: {}]: [{}]: [Accepter] An unknown error occured when attempting to close connection. \n", std::this_thread::get_id(), HDE::get_current_time());
                HDE::reportErrorMessage();
                HDE::Server::logClientInfo("Accepter", ip_str);
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        if (debugging_checkpoints) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] Checkpoint 3 reached.\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        if (HDE::is_rate_limited(std::string(ip_str))) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] Deteched possible DoS attempt from client {}. Closing connection...\n", std::this_thread::get_id(), HDE::get_current_time(), std::string(ip_str));
            try {
                close(client_socket_fd);
            } catch (...) {
                std::cout << std::format("[Thread: {}]: [{}]: [Accepter] An error occured when attempting to close the connection. In the future there will be more details about the error here.\n", std::this_thread::get_id(), HDE::get_current_time());
                HDE::reportErrorMessage();
                HDE::Server::logClientInfo("Accepter", ip_str);
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        ssize_t bytesRead = read(client_socket_fd, local_buf, sizeof(local_buf) - 1);
        if (debugging_checkpoints) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] Checkpoint 4 reached\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        if (bytesRead > 0) [[likely]] {
            local_buf[bytesRead] = '\0';
            addr_lock.lock();
            address_queue.emplace_response(client_socket_fd, std::span(local_buf, bytesRead));
            addr_lock.unlock();
            {
                std::lock_guard<std::mutex> inner_lock(console_mutex);
                std::cout << std::format("[Thread {}]: [{}]: [Accepter] Received information from client {}, data:\n\n{}\n\n", std::this_thread::get_id(), HDE::get_current_time(), std::string(ip_str), std::string(local_buf));
            }
        } else if (bytesRead == 0) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] A client is disconnected to the server. IP: \n", std::this_thread::get_id(), HDE::get_current_time(), std::string(ip_str));
            HDE::reportErrorMessage();
            try {
                close(client_socket_fd);
            } catch (...) {
                std::cout << std::format("[Thread: {}]: [{}]: [Accepter] An error occured when attempting to close connection.\n", std::this_thread::get_id(), HDE::get_current_time());
                HDE::reportErrorMessage();
                HDE::Server::logClientInfo("Accepter", ip_str);
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        } else if (bytesRead >= sizeof(local_buf) - 1) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] A client has a packet that could trigger a buffer overflow, either by an oversized request or a DoS attempt. Client IP: {}. Attempting to close the connection...\n", std::this_thread::get_id(), HDE::get_current_time(), std::string(ip_str));
            try {
                close(client_socket_fd);
            } catch (...) {
                std::cout << std::format("[Thread: {}]: [{}]: [Accepter] An error occured when attempting to close connection.\n", std::this_thread::get_id(), HDE::get_current_time());
                HDE::reportErrorMessage();
                HDE::Server::logClientInfo("Accepter", ip_str);
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        } else [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Accepter] General read error encountered. Closing connection and reporting.\n", std::this_thread::get_id(), HDE::get_current_time());
            HDE::reportErrorMessage();
            try {
                close(client_socket_fd); // The socket MUST be closed here
            } catch (...) {
                std::cout << std::format("[Thread: {}]: [{}]: [Accepter] An error occured when attempting to close connection.\n", std::this_thread::get_id(), HDE::get_current_time());
                HDE::reportErrorMessage();
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
    }
    init_lock.lock();
    std::cout << std::format("[Thread: {}]: [{}]: [Accepter] Accepter loop terminated.\n", std::this_thread::get_id(), HDE::get_current_time());
    init_lock.unlock();
    return;
}
//Runs on independent thread
//Retrieve the incoming request from AddressQueue object, then load the processed request into the ResponderQueue object
void HDE::Server::handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue) {
    std::unique_lock<std::mutex> init_lock(console_mutex);
    std::unique_lock<std::mutex> address_lock(address_queue_mutex, std::defer_lock);
    std::unique_lock<std::mutex> response_lock(responder_queue_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [finished_initialization_ptr = &finished_initialization] { return finished_initialization_ptr -> load(); });
    std::cout << std::format("[Thread: {}]: [{}]: [Handler] Initializing...\n", std::this_thread::get_id(), HDE::get_current_time());
    init_lock.unlock();
    for (;;) {
        if (stop_server.load(std::memory_order_seq_cst)) [[unlikely]] {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Handler] Terminating handler loop...\n", std::this_thread::get_id(), HDE::get_current_time());
            address_queue.closeAllConnections();
            responder_queue.closeAllConnections();
            break;
        }
        struct Request client;
        init_lock.lock();
        std::cout << std::format("[Thread: {}]: [{}]: [Handler] Waiting for tasks...\n", std::this_thread::get_id(), HDE::get_current_time());
        init_lock.unlock();
        {
            std::unique_lock<std::mutex> queue_lock(address_queue_mutex);
            addr_in_addr_queue.wait(queue_lock, [&address_queue] {
                return stop_server.load(std::memory_order_seq_cst) || !address_queue.empty();
            });
            if (stop_server.load(std::memory_order_seq_cst)) [[unlikely]] continue;
            client = address_queue.get_response();
        }
        if (client.location == 0) [[unlikely]] continue;
        if (debugging_checkpoints) [[unlikely]] {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Handler] Checkpoint 1 reached.\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            HDE::Server::logClientInfo("Handler", client.msg);
        }
        //In the future when the server has multiple caches of files this is unsafe; it may cause incorrect behavior.
        //std::string_view contents = main_page_template_cache;
        {
            //Server processing steps here
            //std::lock_guard<std::mutex> lock(file_access_mutex);
            //This step is for when the files are separate and the server has to obtain them. In this case, the file is cached beforehand, so it is completely safe.
            //contents = main_page_template_cache;
        }
        
        //just ignore this triple-scope style for now
        if (debugging_checkpoints) [[unlikely]] {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Handler] Checkpoint 2 reached.\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        {
            std::lock_guard<std::mutex> lock(responder_queue_mutex);
            responder_queue.emplace_response(client.location, main_page_template_cache);
            resp_in_res_queue.notify_one();
        }
        if (debugging_checkpoints) [[unlikely]] {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Handler] Checkpoint 3 reached.\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        if (continuous_responses) [[likely]] continue;
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / HDE::handler_responses_per_second));
            continue;
        }
    }
    init_lock.lock();
    std::cout << std::format("[Thread: {}]: [{}]: [Handler] Handler loop terminated.\n", std::this_thread::get_id(), HDE::get_current_time());
    init_lock.unlock();
    return;
}
//Runs on independent thread
void HDE::Server::responder(HDE::ResponderQueue& response) {
    std::unique_lock<std::mutex> init_lock(console_mutex);
    finish_initialization.wait(init_lock, [finished_initialization_ptr = &finished_initialization] { return finished_initialization_ptr -> load(); });
    std::cout << std::format("[Thread: {}]: [{}]: [Responder] Initializing...\n", std::this_thread::get_id(), HDE::get_current_time());
    init_lock.unlock();
    for (;;) {
        if (stop_server.load(std::memory_order_seq_cst)) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Responder] Terminating responder loop...\n", std::this_thread::get_id(), HDE::get_current_time());
            response.closeAllConnections();
            break;
        }
        struct Response client;
        {
            std::unique_lock<std::mutex> queue_lock(responder_queue_mutex);
            init_lock.lock();
            std::cout << std::format("[Thread: {}]: [{}]: [Responder] Waiting for tasks...\n", std::this_thread::get_id(), HDE::get_current_time());
            init_lock.unlock();
            resp_in_res_queue.wait(queue_lock, [&response] { return stop_server.load(std::memory_order_seq_cst) || !response.empty(); });
            if (stop_server.load(std::memory_order_seq_cst)) continue;
            client = response.get_response();
        }
        if (debugging_checkpoints) [[unlikely]] {
            std::lock_guard<std::mutex> inner_lock(console_mutex);
            std::cout << std::format("[Thread: {}]: [{}]: [Responder] Checkpoint 1 reached.\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        if (client == Response{}) [[unlikely]] continue;
        const char* msg = client.msg.c_str();
        init_lock.lock();
        std::cout << std::format("[Thread: {}]: [{}]: [Responder] Received data from [Handler]. Processing...\n", std::this_thread::get_id(), HDE::get_current_time());
        init_lock.unlock();
        //In the future implement a loop here that keeps track of bytes being sent, then repeatedly spamming packets until remaining bytes = 0
        ssize_t res = write(client.destination, msg, client.msg.length());
        init_lock.lock();
        std::cout << std::format("[Thread: {}]: [{}]: [Responder] Result of variable <res>: {}\n", std::this_thread::get_id(), HDE::get_current_time(), std::to_string(res));
        if (debugging_checkpoints) [[unlikely]] {
            std::cout << std::format("[Thread: {}]: [{}]: [Responder] Checkpooint 2 reached.\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        if (res == -1) [[unlikely]] {
            //case where the server failed to send the message
            std::cout << std::format("[Thread: {}]: [{}]: [Responder] A client failed to receive the data.\n", std::this_thread::get_id(), HDE::get_current_time());
            //try to clean this in the future
            int error_code = errno;
            if (error_code == EAGAIN || error_code == EWOULDBLOCK) [[unlikely]] { //In the future the server might ran out of resources easily, so if possible change [[unlikely]] to [[likely]].
                std::cout << std::format("[Thread: {}]: [{}]: [Responder] The kernel's socket sending buffer is full, try writing again later. Continuously trying again the write() will be implemented in the future (not near).\n", std::this_thread::get_id(), HDE::get_current_time());
                continue;
            } else if (error_code == EPIPE) [[unlikely]] {
                std::cout << std::format("[Thread: {}]: [{}]: [Responder] The socket has been closed by the client while transmission is happening.\n", std::this_thread::get_id(), HDE::get_current_time());
                continue;
            } else if (error_code == ECONNRESET) [[likely]] {
                std::cout << std::format("[Thread: {}]: [{}]: [Responder] The connection is reset by the peer. It could be an abrupt shut down or sent a TCP reset packet.\n", std::this_thread::get_id(), HDE::get_current_time());
                continue;
            } else if (error_code == ETIMEDOUT) [[likely]] {
                std::cout << std::format("[Thread: {}]: [{}]: [Responder] A network time out happened during transmission.\n", std::this_thread::get_id(), HDE::get_current_time());
                continue;
            } else if (error_code == EBADF) [[unlikely]] {
                std::cout << std::format("[Thread: {}]: [{}]: [Responder] The file is invalid; it has either been closed or never opened, or another unknown issue.\n", std::this_thread::get_id(), HDE::get_current_time());
                HDE::reportErrorMessage();
                continue;
            } else if (error_code == EINVAL) [[unlikely]] {
                std::cout << "[Thread " << std::this_thread::get_id() << "]: " << "[" << HDE::get_current_time() << "] [Responder]: The file is valid but is not available for transmission." << std::endl;
                std::cout << std::format("[Thread: {}]: [{}]: [Responder] The file is valid but is not available for transission.\n", std::this_thread::get_id(), HDE::get_current_time());
                HDE::reportErrorMessage();
                continue;
            } else if (error_code == EINTR) [[unlikely]] {
                std::cout << std::format("[Thread: {}]: [{}]: [Responder] The socket has been closed by the client while transmission is happening, or an interrupted system call (normally I.S.Cs are usually harmless). Restarting the write function would be the way to go; implementing a loop to continuosly try the write() in the future (not near).\n", std::this_thread::get_id(), HDE::get_current_time());
                continue;
            } else if (error_code == ENOMEM) [[unlikely]] {
                HDE::reportErrorMessage();
                std::cout << std::format("[Thread: {}]: [{}]: [Responder] The server ran out of memory trying to complete the request. Either there being not enough memory (while creating internal structures), or this is a sign of a possible attack.\n", std::this_thread::get_id(), HDE::get_current_time());
                continue;
            } else [[likely]] {
                HDE::reportErrorMessage();
                std::cout << std::format("[Thread: {}]: [{}]: [Responder] An undocumented error occured.\n", std::this_thread::get_id(), HDE::get_current_time());
                continue;
            }
        } else if (res > 0) [[likely]] {
            //successful tramission
            std::cout << std::format("[Thread: {}]: [{}]: [Responder] Successful data transmissiont to the client.\n", std::this_thread::get_id(), HDE::get_current_time());
        } else if (res == 0) [[unlikely]] {
            //requested to write 0 bytes. typically not an error, but log this event
            std::cout << std::format("[Thread: {}]: [{}]: [Responder] 0 bytes sent to the client. Either they requested 0 bytes or this could be an internal server error causing no bytes to be sent.\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        if (debugging_checkpoints) [[unlikely]] {
            std::cout << std::format("[Thread: {}]: [{}]: [Responder] Checkpoint 2 reached.\n", std::this_thread::get_id(), HDE::get_current_time());
        }
        init_lock.unlock();
        try {
            close(client.destination);
            init_lock.lock();
        } catch (...) {
            init_lock.lock();
            std::cout << std::format("[Thread: {}]: [{}]: [Responder] An error occured while trying to close the connection. The server will force a shut down.\n", std::this_thread::get_id(), HDE::get_current_time());
            HDE::reportErrorMessage();
            HDE::Server::logClientInfo("Responder", client.msg);
            shutdown(client.destination, SHUT_RDWR);
        }
        std::cout << "========================= Log Separator =========================" << std::endl;
        init_lock.unlock();
        if (HDE::continuous_responses) continue;
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / HDE::responder_responses_per_second));
            continue;
        }
    }
    init_lock.lock();
    std::cout << std::format("[Thread: {}]: [{}]: [Responder] Responder loop terminated.\n", std::this_thread::get_id(), HDE::get_current_time());
    init_lock.unlock();
    return;
}

void HDE::Server::launch() {
    std::unique_lock<std::mutex> global_lock(console_mutex);
    if (HDE::totalUsedThreads > HDE::NUM_THREADS) [[unlikely]] {
        std::cout << std::format("[Thread: {}]: [{}]: [Main Thread] Invalid thread allocation. The amount of allocated threads is: {} threads. The amount of available threads: {} threads. Exiting...\n", std::this_thread::get_id(), HDE::get_current_time(), HDE::totalUsedThreads, HDE::NUM_THREADS);
        exit(EXIT_FAILURE);
    } else if (HDE::threadsForAccepter > HDE::NUM_THREADS - 1 || HDE::threadsForHandler > HDE::NUM_THREADS - 1 || HDE::threadsForResponder > HDE::NUM_THREADS - 1) [[unlikely]] {
        std::cout << std::format("[Thread: {}]: [{}]: [Main Thread] Invalid thread allocation. The maximum thread count for any task Accepter, Handler, or Responder is {} threads, thy shall not go over that. Exiting...\n", std::this_thread::get_id(), HDE::get_current_time(), std::to_string(HDE::NUM_THREADS - 2));
        exit(EXIT_FAILURE);
    }
    //can totally remove, it's just the upper cap for the variables; they won't even be used anyway.
    if (HDE::handler_responses_per_second > 1000) [[unlikely]] {
        HDE::handler_responses_per_second = 1000;
    }
    if (HDE::responder_responses_per_second > 1000) [[unlikely]] {
        HDE::responder_responses_per_second = 1000;
    }
    std::ios_base::sync_with_stdio(HDE::IOSynchronization);
    HDE::AddressQueue address_queue;
    HDE::ResponderQueue responder_queue;
    std::vector<std::jthread> processes(HDE::totalUsedThreads);
    //initialize the threads
    for (size_t i = 0; i < HDE::threadsForAccepter; ++i) {
        processes[i] = std::jthread(&HDE::Server::accepter, this, std::ref(address_queue));
    }
    for (size_t i = HDE::threadsForAccepter; i < HDE::threadsForAccepter + HDE::threadsForHandler; ++i) {
        processes[i] = std::jthread(&HDE::Server::handler, this, std::ref(address_queue), std::ref(responder_queue));
    }
    for (size_t i = HDE::threadsForAccepter + HDE::threadsForHandler; i < HDE::totalUsedThreads; ++i) {
        processes[i] = std::jthread(&HDE::Server::responder, this, std::ref(responder_queue));
    }
    std::cout << std::format("[Thread: {}]: [{}]: [Main Thread] Threads initialized.\n", std::this_thread::get_id(), HDE::get_current_time());
    finished_initialization = true;
    for (int i = 0; i < processes.size(); ++i) {
        finish_initialization.notify_all();
    }
    global_lock.unlock();
    //let all of the threads initialized first
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    global_lock.lock();
    std::cout << std::format("[Thread: {}]: [{}]: [Main Thread] Main thread finished executing.\n", std::this_thread::get_id(), HDE::get_current_time());
    global_lock.unlock();
}


//side dev notes

/*Example for cpu pinning, required libraries already included.
void pin_thread_to_core(std::thread& t, int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    
    pthread_t native = t.native_handle();
    pthread_setaffinity_np(native, sizeof(cpu_set_t), &cpuset);
}

// In launch():
for (size_t i = 0; i < threadsForAccepter; ++i) {
    processes[i] = std::jthread(&Server::accepter, this, std::ref(address_queue));
    pin_thread_to_core(processes[i], i % num_cores);  // Pin to specific core
}
*/

/* To implement protocol buffers - example
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
