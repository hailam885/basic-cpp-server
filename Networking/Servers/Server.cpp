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

//in the future, if possible create a struct for each of these mutexes/conditional variables and add padding; but only do it for frequently-accessed ones.

alignas(CACHE_LINE_SIZE) socklen_t addrlen = sizeof(struct sockaddr_in);
//this is the samething as sizeof(buffer), which probabyl evaluates to HDE::MAX_BUFFER_SIZE anyway.
alignas(CACHE_LINE_SIZE) constexpr size_t buf_size = HDE::MAX_BUFFER_SIZE;

//definitions
alignas(CACHE_LINE_SIZE) std::mutex address_queue_mutex;
alignas(CACHE_LINE_SIZE) std::mutex responder_queue_mutex;
alignas(CACHE_LINE_SIZE) std::mutex address_cv_mutex;
alignas(CACHE_LINE_SIZE) std::mutex response_cv_mutex;
alignas(CACHE_LINE_SIZE) std::mutex r_e_m_mutex;
alignas(CACHE_LINE_SIZE) std::mutex clean_up_mutex;
alignas(CACHE_LINE_SIZE) std::mutex init_mutex;
alignas(CACHE_LINE_SIZE) std::mutex general_mutex;
alignas(CACHE_LINE_SIZE) std::mutex file_access_mutex; //to account for fstream's thread-risky nature
alignas(CACHE_LINE_SIZE) std::mutex rate_limited_mutex;
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
    if (!message.empty() && static_cast<int>(HDE::log_level) >= 2) [[likely]] {
        LOG_INFO(logger, "[Thread {}]: [{}] logClientInfo(): {}", get_thread_id_cached(), processing_component, message);
    } else if (static_cast<int>(HDE::log_level) >= 2) [[unlikely]] {
        LOG_INFO(logger, "[Thread {}]: [{}] logClientInfo(): <empty>", get_thread_id_cached(), processing_component);
    } else {
        return;
    }
}
//Thread-safe, only prints if static_cast<int>(HDE::log_level) is set to anything higher than 0.
inline void HDE::reportErrorMessage(quill::Logger* logger) {
    int error_code = errno;
    if (static_cast<int>(HDE::log_level) >= 1) {
        LOG_INFO(logger, "[Thread {}]: An error has occured (Description, if any, line above).", get_thread_id_cached());
    }
    if (errno == EINTR) [[unlikely]] {
        if (static_cast<int>(HDE::log_level) >= 1) LOG_INFO(logger, "[Thread {}]: Message: A possible interrupted system call is detected.", get_thread_id_cached());
    } else if (errno == EMFILE || errno == ENFILE) [[unlikely]] {
        if (static_cast<int>(HDE::log_level) >= 1) LOG_INFO(logger, "[Thread {}]: Message: The server is using a lot of resources (Too many open files). Check immediately.", get_thread_id_cached());
    } else if (static_cast<int>(HDE::log_level) >= 1) [[likely]] {
        LOG_INFO(logger, "[Thread {}]: Message: {}", get_thread_id_cached(), strerror(errno));
    } else return;
}
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
//(Probably implemented in the future) Function will repeatedly try to add; and will wait for 
void HDE::AddressQueue::emplace_response(int loc, std::span<const char> data, quill::Logger* logger) {
    {
        std::lock_guard<std::mutex> lock(address_queue_mutex);
        //have a wait condition here that waits until responder queue has space
        if (address_queue.size() < HDE::max_incoming_address_queue_size) [[likely]] {
            address_queue.emplace(loc, std::string(data.data(), data.size()));
        } else [[unlikely]] {
            if (static_cast<int>(HDE::log_level) >= 2) LOG_INFO(logger, "[Thread {}]: Rejecting client due to incoming_address_queue_size overflow. Overflow limit: {} clients.", get_thread_id_cached(), HDE::max_incoming_address_queue_size);
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
        std::lock_guard<std::mutex> lock(address_queue_mutex);
        //have a wait condition here that waits until responder queue has space
        if (address_queue.size() < HDE::max_incoming_address_queue_size) [[likely]] {
            address_queue.emplace(location, msg);
        } else [[unlikely]]  {
            if (static_cast<int>(HDE::log_level) >= 2) {
                LOG_INFO(logger, "[Thread {}]: Rejecting client due to incoming_address_queue_size overflow. Overflow limit: {} clients.", get_thread_id_cached(), HDE::max_incoming_address_queue_size);
            } else return;
        }
    }
    addr_in_addr_queue.notify_one();
}
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
struct Request HDE::AddressQueue::get_response() {
    std::lock_guard<std::mutex> lock(address_queue_mutex);
    if (!address_queue.empty()) [[likely]] {
        struct Request res = std::move(address_queue.front());
        address_queue.pop();
        return res; //Allow for RVO
    } else [[unlikely]] return Request{};
}
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
int HDE::AddressQueue::get_size() const noexcept {
    std::lock_guard<std::mutex> lock(address_queue_mutex);
    return address_queue.size();
}
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
void HDE::AddressQueue::closeAllConnections() {
    std::vector<int> fds_to_close;
    {
        std::lock_guard<std::mutex> lock(address_queue_mutex);
        while (!address_queue.empty()) {
            if (address_queue.front().location != -1) [[likely]] {
                fds_to_close.push_back(address_queue.front().location);
            address_queue.pop();
            }
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
//Thread-safe, do not lock address_queue_mutex within the same scope of the function
bool HDE::AddressQueue::empty() const noexcept {
    std::lock_guard<std::mutex> lock(address_queue_mutex);
    return address_queue.empty();
}
//will not add element if adding them means allResponses's size exceeds HDE::maxResponsesQueue.
//in the future if the website grows might switch [[likely]] with [[unlikely]]
/*void HDE::ResponderQueue::emplace_response(int loc, std::span<const char> data, quill::Logger* logger) noexcept {
    std::lock_guard<std::mutex> lock(responder_queue_mutex);
    if (allResponses.size() <= HDE::max_responses_queue_size) [[likely]] {
        allResponses.emplace(loc, std::string(data.data(), data.size()));
        resp_in_res_queue.notify_one();
    } else [[unlikely]] {
        if (static_cast<int>(HDE::log_level) >= 2) LOG_INFO(logger, "[Thread {}]: Rejecting client due to max_responses_queue_size overflow; Overflow limit: {} clients.", get_thread_id_cached(), std::to_string(HDE::max_responses_queue_size));
    }
}*/
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
void HDE::ResponderQueue::emplace_response(const int destination, const std::string_view msg, quill::Logger* logger) {
    {
        std::lock_guard<std::mutex> lock(responder_queue_mutex);
        if (allResponses.size() <= HDE::max_responses_queue_size) [[likely]] {
            allResponses.emplace(destination, msg);
        } else [[unlikely]] {
            //have a wait condition here that waits until responder queue has space
            if (static_cast<int>(HDE::log_level) >= 1) {
                LOG_INFO(logger, "[Thread {}]: Rejecting client due to max_responses_queue_size overflow; Overflow limit: {} clients.", get_thread_id_cached(), HDE::max_responses_queue_size);
            }
        }
        return;
    }
    resp_in_res_queue.notify_one();
}
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
struct Response HDE::ResponderQueue::get_response() noexcept {
    std::lock_guard<std::mutex> lock(responder_queue_mutex);
    if (!allResponses.empty()) [[likely]] {
        struct Response destination = std::move(allResponses.front());
        allResponses.pop();
        return destination;
    } else [[unlikely]] return Response{};
}
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
int HDE::ResponderQueue::get_size() const noexcept {
    std::lock_guard<std::mutex> lock(responder_queue_mutex);
    return allResponses.size();
}
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
void HDE::ResponderQueue::closeAllConnections() {
    std::vector<int> fds_to_close;
    {
        std::lock_guard<std::mutex> lock(responder_queue_mutex);
        while (!allResponses.empty()) {
            if (allResponses.front().destination != -1) [[likely]] {
                fds_to_close.push_back(allResponses.front().destination);
            allResponses.pop();
            }
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
//Thread-safe, do not lock responder_queue_mutex within the same scope of the function
bool HDE::ResponderQueue::empty() const noexcept {
    std::lock_guard<std::mutex> lock(responder_queue_mutex);
    return allResponses.empty();
}

//Constructor
HDE::Server::Server(quill::Logger* logger) : SimpleServer(AF_INET, SOCK_STREAM, 0, HDE::Port, INADDR_ANY, HDE::queueCount) {
    HDE::Server::launch(logger);
}

//probably not ever gonna use this function but don't delete it we might, and i say might need it in the future (no promises)
void HDE::clean_server_shutdown(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue) {
    serverState.stop_server.store(true, std::memory_order_seq_cst);
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
    std::lock_guard<std::mutex> lock(rate_limited_mutex);
    auto now = std::chrono::steady_clock::now();
    RateLimiter& limiter = limiters[std::string(client_ip)];
    size_t recent = limiter.count_recent(std::chrono::seconds(1));
    if (recent >= HDE::MAX_CONNECTIONS_PER_SECOND) [[unlikely]] return true;
    limiter.add(now);
    return false;
}
//Runs on independent thread
void HDE::Server::accepter(HDE::AddressQueue& address_queue, quill::Logger* logger) {
    std::unique_lock<std::mutex> init_lock(init_mutex);
    std::unique_lock<std::mutex> addr_lock(address_queue_mutex, std::defer_lock);
    //std::unique_lock<std::mutex> add_in_queue(address_in_queue_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [] {
        return serverState.finished_initialization.load(std::memory_order_acquire);
    });
    LOG_INFO(logger, "[Thread {}]: [Accepter] Initializing...", get_thread_id_cached());
    init_lock.unlock();
    char local_buf[sizeof(buffer)];
    char ip_str[INET6_ADDRSTRLEN];
    int client_socket_fd;
    const size_t MAX_PACKET_SIZE = sizeof(buffer) - 1;
    int res;
    ssize_t bytesRead;
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
                if (static_cast<int>(HDE::log_level) >= 2) [[unlikely]] LOG_INFO(logger, "[Thread {}]: [Accepter] No activity in 5 seconds.", get_thread_id_cached());
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
        if (serverState.stop_server.load(std::memory_order_relaxed)) [[unlikely]] break;
        if (static_cast<int>(HDE::log_level) >= 1) {
            LOG_INFO(logger, "[Thread {}]: [Accepter] Waiting for requests...", get_thread_id_cached());
        }
        struct sockaddr_in address = get_socket() -> get_address();
        client_socket_fd = accept(get_socket() -> get_sock(), reinterpret_cast<struct sockaddr*>(&address), reinterpret_cast<socklen_t*>(&addrlen));
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Accepter] Checkpoint 1 reached.", get_thread_id_cached());
        }
        if (client_socket_fd < 0) [[unlikely]] {
            if (static_cast<int>(HDE::log_level) >= 1) LOG_INFO(logger, "[Thread {}]: [Accepter] A client cannot connect to the server.", get_thread_id_cached());
            HDE::reportErrorMessage(logger);
            continue;
        }
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Accepter] Checkpoint 2 reached.", get_thread_id_cached());
        }
        res = getnameinfo(reinterpret_cast<struct sockaddr*>(&address), sizeof(address), ip_str, INET6_ADDRSTRLEN, nullptr, 0, NI_NUMERICHOST);
        if (res != 0) [[unlikely]] {
            if (static_cast<int>(HDE::log_level) >= 2) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] A client has an unknown IP address. The server will attempt to close the connection; and shuts it down if that fails.", get_thread_id_cached());
            }
            HDE::reportErrorMessage(logger);
            if (close(client_socket_fd) == -1) {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Accepter] Checkpoint 3 reached.", get_thread_id_cached());
        }
        if (HDE::is_rate_limited(std::string(ip_str)) && HDE::enable_DoS_protection) [[unlikely]] {
            if (static_cast<int>(HDE::log_level) >= 1) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] Deteched possible DoS attempt from client {}. The server will attempt to close the connection, and shuts it if that fails.", get_thread_id_cached(), ip_str);
            }
            if (close(client_socket_fd) == -1) {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
        bytesRead = read(client_socket_fd, local_buf, sizeof(local_buf) - 1);
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Accepter] Checkpoint 4 reached.", get_thread_id_cached());
        }
        if (bytesRead > 0 && bytesRead < sizeof(local_buf) - 1) [[likely]] {
            local_buf[bytesRead] = '\0'; //null terminator
            if (static_cast<int>(HDE::log_level) >= 3) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] About to acquire address_queue_mutex in .emplate_response()", get_thread_id_cached());
            }
            address_queue.emplace_response(client_socket_fd, std::span(local_buf, bytesRead), logger);
            if (static_cast<int>(HDE::log_level) >= 2) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] Received data from {}:\n{}", get_thread_id_cached(), ip_str, std::string(local_buf));
            } else if (HDE::log_level == DECREASED) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] Client {} is connected.", get_thread_id_cached(), ip_str);
            }
            continue;
        } else if (bytesRead == 0) [[unlikely]] {
            if (static_cast<int>(HDE::log_level) >= 1) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] A client is disconnected to the server. No bytes are read. IP: {}. The server will attempt to close the connection, and shuts it down if that fails.", get_thread_id_cached(), ip_str);
            }
            HDE::reportErrorMessage(logger);
            if (close(client_socket_fd) == -1) {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        } else if (bytesRead >= sizeof(local_buf) - 1) [[unlikely]] {
            if (static_cast<int>(HDE::log_level) >= 1) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] A client has a packet that could trigger a buffer overflow, either by an oversized request or a DoS attempt. Client IP: {}. The server will attempt to close the connection, and shuts it down if that fails.", get_thread_id_cached(), ip_str);
            }
            if (close(client_socket_fd) == -1) {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        } else {
            if (static_cast<int>(HDE::log_level) >= 2) {
                LOG_INFO(logger, "[Thread {}]: [Accepter] General read error encountered. The server will attempt to close the connection, and shuts it down if that fails.", get_thread_id_cached());
            }
            HDE::reportErrorMessage(logger);
            if (close(client_socket_fd) == -1) {
                shutdown(client_socket_fd, SHUT_RDWR);
            }
            continue;
        }
    }
    /*#ifdef __APPLE__
        close(kq);
    #elif __linux__
        close(epoll_fd);
    #endif*/
    LOG_INFO(logger, "[Thread {}]: [Accepter] Accepter loop terminated.", get_thread_id_cached());
    return;
}
//Runs on independent thread
//Retrieve the incoming request from AddressQueue object, then load the processed request into the ResponderQueue object
void HDE::Server::handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue, quill::Logger* logger) {
    std::unique_lock<std::mutex> init_lock(init_mutex);
    std::unique_lock<std::mutex> addr_lock(address_queue_mutex, std::defer_lock);
    std::unique_lock<std::mutex> resp_lock(responder_queue_mutex, std::defer_lock);
    std::unique_lock<std::mutex> cv_lock(address_cv_mutex, std::defer_lock);
    //std::unique_lock<std::mutex> add_in_queue(address_in_queue_mutex, std::defer_lock);
    //std::unique_lock<std::mutex> resp_in_queue(response_in_queue_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [] { 
        return serverState.finished_initialization.load(std::memory_order_acquire);
    });
    LOG_INFO(logger, "[Thread {}]: [Handler] Initializing...", get_thread_id_cached());
    init_lock.unlock();
    std::string temp;
    std::string contents;
    struct Request client;
    size_t content_length;
    for (;;) {
        if (serverState.stop_server.load(std::memory_order_relaxed)) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Handler] Terminating handler loop...", get_thread_id_cached());
            address_queue.closeAllConnections();
            responder_queue.closeAllConnections();
            break;
        }
        if (static_cast<int>(HDE::log_level) >= 1) {
            LOG_INFO(logger, "[Thread {}]: [Handler] Waiting for tasks...", get_thread_id_cached());
        }
        {
            if (static_cast<int>(HDE::log_level) >= 3) {
                LOG_INFO(logger, "[Thread {}]: [Handler] Acquired address_cv_mutex", get_thread_id_cached());
            }
            cv_lock.lock();
            addr_in_addr_queue.wait(cv_lock, [&address_queue] {
                return serverState.stop_server.load(std::memory_order_seq_cst) || !address_queue.empty();
            });
            cv_lock.unlock();
        }
        if (serverState.stop_server.load(std::memory_order_seq_cst)) [[unlikely]] continue;
        //calling get_response() without the lock; double locking causes a deadlock
        if (static_cast<int>(HDE::log_level) >= 3) {
            LOG_INFO(logger, "[Thread {}]: [Handler] (checkpoint)", get_thread_id_cached());
        }
        client = address_queue.get_response();
        if (client.location == 0) [[unlikely]] continue;
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Handler] Checkpoint 1 reached.", get_thread_id_cached());
        }
        HDE::Server::logClientInfo("Handler", client.msg, logger);
        //<-- Server processing steps -->
        {
            //actually in the future try to implement an advanced file caching system that run on startup to avoid unnecessary operations
            //client request is stored in client.msg
            std::lock_guard<std::mutex> lock(file_access_mutex);
            std::fstream inputFile(html_file_path);
            if (!inputFile.is_open()) [[unlikely]] {
                LOG_INFO(logger, "FATAL: Cannot open file: {}", html_file_path);
                exit(EXIT_FAILURE);
            }
            temp = std::string((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
            inputFile.close();
        }
        content_length = temp.length();
        contents.reserve(content_length + 100);
        contents = std::format(
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: {}\r\n"
            "Connection: close\r\n"
            "\r\n{}",
            content_length, temp
        );
        if (contents.empty()) [[unlikely]] {
            LOG_INFO(logger, "FATAL: File is empty.");
            exit(EXIT_FAILURE);
        }
        if (static_cast<int>(HDE::log_level) >= 1) {
            LOG_INFO(logger, "Template cache loaded: {} bytes", contents.length());
        }
        // <-- End server processing steps zone -->
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Handler] Checkpoint 2 reached.", get_thread_id_cached());
        }
        {
            //std::lock_guard<std::mutex> lock(responder_queue_mutex); <- comment out to avoid double lock
            if (static_cast<int>(HDE::log_level) >= 2) {
                LOG_INFO(logger, "[Thread {}]: [Handler] Acquired responder_queue_mutex", get_thread_id_cached());
            }
            responder_queue.emplace_response(client.location, contents, logger);
            resp_in_res_queue.notify_one();
        }
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Handler] Checkpoint 3 reached.", get_thread_id_cached());
        }
        if (HDE::continuous_responses) [[likely]] continue;
        else [[unlikely]] {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / HDE::handler_responses_per_second));
            continue;
        }
    }
    LOG_INFO(logger, "[Thread {}]: [Handler] Handler loop terminated.", get_thread_id_cached());
    return;
}
//Runs on independent thread
void HDE::Server::responder(HDE::ResponderQueue& response, quill::Logger* logger) {
    std::unique_lock<std::mutex> init_lock(init_mutex);
    std::unique_lock<std::mutex> cv_lock(response_cv_mutex, std::defer_lock);
    //std::unique_lock<std::mutex> resp_in_queue(response_in_queue_mutex, std::defer_lock);
    finish_initialization.wait(init_lock, [] {
        return serverState.finished_initialization.load(std::memory_order_acquire);
    });
    LOG_INFO(logger, "[Thread {}]: [Responder] Initializing...", get_thread_id_cached());
    init_lock.unlock();
    struct Response client;
    const char* msg;
    ssize_t res;
    for (;;) {
        if (serverState.stop_server.load(std::memory_order_relaxed)) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Responder] Terminating responder loop...", get_thread_id_cached());
            response.closeAllConnections();
            break;
        }
        {
            if (static_cast<int>(HDE::log_level) >= 3) LOG_INFO(logger, "[Thread {}]: [Responder] Acquired responder_cv_mutex", get_thread_id_cached());
            if (static_cast<int>(HDE::log_level) >= 1) LOG_INFO(logger, "[Thread {}]: [Responder] Waiting for tasks...", get_thread_id_cached());
            cv_lock.lock();
            resp_in_res_queue.wait(cv_lock, [&response] {
                return serverState.stop_server.load(std::memory_order_acquire) || !response.empty();
            });
            cv_lock.unlock();
        }
        if (serverState.stop_server.load(std::memory_order_seq_cst)) [[unlikely]] continue;
        client = response.get_response();
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Responder] Checkpoint 1 reached.", get_thread_id_cached());
        }
        if (client == Response{}) [[unlikely]] continue;
        msg = client.msg.c_str();
        if (static_cast<int>(HDE::log_level) >= 1) {
            LOG_INFO(logger, "[Thread {}]: [Responder] Received data from [Handler]. Processing...", get_thread_id_cached());
        }
        //In the future implement a loop here that keeps track of bytes being sent, then repeatedly spamming packets until remaining bytes = 0
        res = write(client.destination, msg, client.msg.length());
        if (static_cast<int>(HDE::log_level) >= 2) {
            LOG_INFO(logger, "[Thread {}]: [Responder] Result of variable <res>: {}", get_thread_id_cached(), std::to_string(res));
        }
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Responder] Checkpooint 2 reached.", get_thread_id_cached());
        }
        if (res == -1) [[unlikely]] {
            //case where the server failed to send the message
            if (static_cast<int>(HDE::log_level) >= 2) {
                LOG_INFO(logger, "[Thread {}]: [Responder] ERROR: A client failed to receive the data.", get_thread_id_cached());
            }
            //try to clean this in the future
            int error_code = errno;
            if (error_code == EAGAIN || error_code == EWOULDBLOCK) [[unlikely]] { //In the future the server might ran out of resources easily, so if possible change [[unlikely]] to [[likely]].
                if (static_cast<int>(HDE::log_level) >= 3) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] The kernel's socket sending buffer is full, try writing again later. Continuously trying again the write() will be implemented in the future (not near).", get_thread_id_cached());
                }
                continue;
            } else if (error_code == EPIPE) [[unlikely]] {
                if (static_cast<int>(HDE::log_level) >= 3) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] The socket has been closed by the client while transmission is happening.", get_thread_id_cached());
                }
                continue;
            } else if (error_code == ECONNRESET) [[likely]] {
                if (static_cast<int>(HDE::log_level) >= 3) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] The connection is reset by the peer. It could be an abrupt shut down or sent a TCP reset packet.", get_thread_id_cached());
                }
                continue;
            } else if (error_code == ETIMEDOUT) [[unlikely]] {
                if (static_cast<int>(HDE::log_level) >= 3) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] A network time out happened during transmission.", get_thread_id_cached());
                }
                continue;
            } else if (error_code == EBADF) [[unlikely]] {
                if (static_cast<int>(HDE::log_level) >= 3) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] The file is invalid; it has either been closed or never opened, or another unknown issue.", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            } else if (error_code == EINVAL) [[unlikely]] {
                if (static_cast<int>(HDE::log_level) >= 3) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] The file is valid but is not available for transission.", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            } else if (error_code == EINTR) [[unlikely]] {
                if (static_cast<int>(HDE::log_level) >= 3) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] The socket has been closed by the client while transmission is happening, or an interrupted system call (normally I.S.Cs are usually harmless). Restarting the write function would be the way to go; implementing a loop to continuosly try the write() in the future (not near).", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            } else if (error_code == ENOMEM) [[unlikely]] {
                if (static_cast<int>(HDE::log_level) >= 3) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] The server ran out of memory trying to complete the request. Either there being not enough memory (while creating internal structures), or this is a sign of a possible attack.", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            } else [[likely]] {
                if (static_cast<int>(HDE::log_level) >= 2) {
                    LOG_INFO(logger, "[Thread {}]: [Responder] An undocumented error occured.", get_thread_id_cached());
                }
                HDE::reportErrorMessage(logger);
                continue;
            }
        } else if (res > 0) [[likely]] {
            //successful tramission
            if (static_cast<int>(HDE::log_level) >= 1) {
                LOG_INFO(logger, "[Thread {}]: [Responder] Successful data transmissiont to the client.", get_thread_id_cached());
            }
        } else if (res == 0) [[unlikely]] {
            //requested to write 0 bytes. typically not an error, but log this event
            if (static_cast<int>(HDE::log_level) >= 2) {
                LOG_INFO(logger, "[Thread {}]: [Responder] 0 bytes sent to the client. Either they requested 0 bytes or this could be an internal server error causing no bytes to be sent.", get_thread_id_cached());
            }
        }
        if (static_cast<int>(HDE::log_level) >= 3) [[unlikely]] {
            LOG_INFO(logger, "[Thread {}]: [Responder] Checkpoint 2 reached.", get_thread_id_cached());
        }
        if (close(client.destination) == -1) {
            if (static_cast<int>(HDE::log_level) >= 3) {
                LOG_INFO(logger, "[Thread {}]: [Responder] An error occured while trying to close the connection. The server will force a shut down.", get_thread_id_cached());
            }
            HDE::reportErrorMessage(logger);
            HDE::Server::logClientInfo("Responder", client.msg, logger);
            shutdown(client.destination, SHUT_RDWR);
        }
        if (static_cast<int>(HDE::log_level) >= 2) {
            LOG_INFO(logger, "========================= Log Separator =========================");
        }
        else if (HDE::log_level == MINIMAL || HDE::log_level == DECREASED) {
            LOG_INFO(logger, "A client is processed by the server.");
        }
        if (HDE::continuous_responses) [[likely]] continue;
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / HDE::responder_responses_per_second));
            continue;
        }
    }
    LOG_INFO(logger, "[Thread {}]: [Responder] Responder loop terminated.", get_thread_id_cached());
    return;
}

void HDE::Server::launch(quill::Logger* logger) {
    //Checking server configurations before start
    if (HDE::totalUsedThreads > HDE::NUM_THREADS) [[unlikely]] {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The amount of allocated threads is: {} threads. The amount of available threads: {} threads. Exiting...", get_thread_id_cached(), HDE::totalUsedThreads, HDE::NUM_THREADS);
        exit(EXIT_FAILURE);
    } else if (HDE::threadsForAccepter > HDE::NUM_THREADS - 1 || HDE::threadsForHandler > HDE::NUM_THREADS - 1 || HDE::threadsForResponder > HDE::NUM_THREADS - 1) [[unlikely]] {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The maximum thread count for any task Accepter, Handler, or Responder is {} threads, thy shall not go over that. Exiting...", get_thread_id_cached(), std::to_string(HDE::NUM_THREADS - 2));
        exit(EXIT_FAILURE);
    } else if (HDE::threadsForAccepter < 1 || HDE::threadsForHandler < 1 || HDE::threadsForResponder < 1) {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The minimum value for each tasks must be 1 threads.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::totalUsedThreads < 3) {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid thread allocation. The minimum value for total used threads is 3. The amount allocated: {}", HDE::get_thread_id_cached(), std::to_string(HDE::totalUsedThreads));
        exit(EXIT_FAILURE);
    } else if (HDE::queueCount < 1) {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid queueCount configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::MAX_CONNECTIONS_PER_SECOND < 1) {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid MAX_CONNECTIONS_PER_SECOND configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::max_incoming_address_queue_size < 1) {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid max_incoming_address_queue_size configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::max_responses_queue_size < 1) {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid max_responses_queue_size configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (HDE::MAX_BUFFER_SIZE < 1) {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid MAX_BUFFER_SIZE configuration. Normally I'd recommend setting the client request size in bytes to around 30000.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } else if (static_cast<int>(HDE::log_level) < 0) {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] Invalid log_level configuration.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    }
    if (HDE::NUM_THREADS < 1) {
        LOG_INFO(logger, "[Thread {}]: [Main Thread] This is not your fault; the server doesn't return a valid thread amount.", HDE::get_thread_id_cached());
        exit(EXIT_FAILURE);
    } 
    //can totally remove, it's just the upper cap for the variables; they won't even be used anyway, they should be disabled to get max throughput
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
    for (size_t i = 0; i < HDE::threadsForAccepter; ++i) processes[i] = std::jthread(&HDE::Server::accepter, this, std::ref(address_queue), logger);
    for (size_t i = HDE::threadsForAccepter; i < HDE::threadsForAccepter + HDE::threadsForHandler; ++i) processes[i] = std::jthread(&HDE::Server::handler, this, std::ref(address_queue), std::ref(responder_queue), logger);
    for (size_t i = HDE::threadsForAccepter + HDE::threadsForHandler; i < HDE::totalUsedThreads; ++i) processes[i] = std::jthread(&HDE::Server::responder, this, std::ref(responder_queue), logger);
    LOG_INFO(logger, "[Thread {}]: [Main Thread] Threads initialized.", get_thread_id_cached());
    serverState.finished_initialization.store(true, std::memory_order_release);
    for (int i = 0; i < processes.size(); ++i) finish_initialization.notify_all();
    LOG_INFO(logger, "[Thread {}]: [Main Thread] Main thread finished executing.", get_thread_id_cached());
}

#ifdef __APPLE__
    int pin_thread_to_core(int cpu_id) {
        //just keep this empty it's kinda useless but dont delete it
    }
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
