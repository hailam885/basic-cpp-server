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
#include <regex>
#include <sched.h>
#include <shared_mutex>
//#include <simd/simd.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <span>
#include <sstream>
#include <string>
#include <string.h>
#include <string_view>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
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
        if (destination == other.destination && msg == other.msg) return true;
        else return false;
    }
    Response() = default;
    Response(int dest, std::string_view message) : destination(dest), msg(message) {};
    Response(int dest, const char* data, size_t len) : destination(dest), msg(data, len) {};
};

template <typename T, size_t Capacity>
class OptimizedQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    //static_assert(sizeof(T) <= CACHE_LINE_SIZE, "T should fit in cache line");
    private:
        struct Slot {
            std::atomic<uint64_t> sequence;
            T data;
            //char padding[CACHE_LINE_SIZE - sizeof(std::atomic<uint64_t>) - sizeof(T)];
        };
        /*alignas(M2_PAGE_SIZE)*/ Slot buffer[Capacity];
        alignas(CACHE_LINE_SIZE) struct {
            uint64_t enqueue_pos;
            uint64_t cached_dequeue_pos;
            uint64_t enqueue_count;  // Statistics
            char padding[CACHE_LINE_SIZE - 3 * sizeof(uint64_t)];
        } producer_cache;
        // Consumer-only cache line (E-core or P-core reads here)
        alignas(CACHE_LINE_SIZE) struct {
            uint64_t dequeue_pos;
            uint64_t cached_enqueue_pos;
            uint64_t dequeue_count;  // Statistics
            char padding[CACHE_LINE_SIZE - 3 * sizeof(uint64_t)];
        } consumer_cache;
        alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> shared_enqueue_pos{0};
        alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> shared_dequeue_pos{0};
        static constexpr uint64_t UPDATE_THRESHOLD = 64; //update shared position every N operations
    public:
        OptimizedQueue() {
            for (size_t i = 0; i < Capacity; ++i) {
                buffer[i].sequence.store(i, std::memory_order_relaxed);
            }
            producer_cache.enqueue_pos = 0;
            producer_cache.cached_dequeue_pos = 0;
            producer_cache.enqueue_count = 0;
            consumer_cache.dequeue_pos = 0;
            consumer_cache.cached_enqueue_pos = 0;
            consumer_cache.dequeue_count = 0;
            //touch all pages to prefault them (avoid page faults in fast path)
            for (size_t i = 0; i < Capacity; i += M2_PAGE_SIZE / sizeof(Slot)) {
                buffer[i].sequence.load(std::memory_order_relaxed);
            }
        }
        bool enqueue(T&& value) noexcept { //producer only
            uint64_t pos = producer_cache.enqueue_pos;
            Slot& slot = buffer[pos & (Capacity - 1)];
            M2_PREFETCH_WRITE(&buffer[(pos + 1) & (Capacity - 1)]);
            //__builtin_prefetch((&buffer[(pos + 1) & (Capacity - 1)]), 1, 3);
            uint64_t seq = slot.sequence.load(std::memory_order_acquire); // arm64 load-exclusive: atomic read with exclusive monitor
            if (seq != pos) [[unlikely]] { // check if slot ready for writing
                if (pos - producer_cache.cached_dequeue_pos >= Capacity) {
                    producer_cache.cached_dequeue_pos = shared_dequeue_pos.load(std::memory_order_acquire);
                    if (pos - producer_cache.cached_dequeue_pos >= Capacity) return false; // Queue is full
                }
                return false;
            }
            __builtin_prefetch(&slot, 1, 3);
            slot.data = std::move(value);
            slot.sequence.store(pos + 1, std::memory_order_release); // arm64 store-exclusive: atomic write with release semantics
            producer_cache.enqueue_pos++;
            producer_cache.enqueue_count++;
            if ((producer_cache.enqueue_count & (UPDATE_THRESHOLD - 1)) == 0) [[unlikely]] shared_enqueue_pos.store(producer_cache.enqueue_pos, std::memory_order_release); // periodically update shared position (minimize cache coherence)
            return true;
        }
        bool enqueue(const T& value) noexcept { // Overload for const reference
            uint64_t pos = producer_cache.enqueue_pos;
            Slot& slot = buffer[pos & (Capacity - 1)];
            M2_PREFETCH_WRITE(&buffer[(pos + 1) & (Capacity - 1)]);
            //__builtin_prefetch((&buffer[(pos + 1) & (Capacity - 1)]), 1, 3);
            uint64_t seq = slot.sequence.load(std::memory_order_acquire);
            if (seq != pos) [[unlikely]] {
                if (pos - producer_cache.cached_dequeue_pos >= Capacity) {
                    producer_cache.cached_dequeue_pos = shared_dequeue_pos.load(std::memory_order_acquire);
                    if (pos - producer_cache.cached_dequeue_pos >= Capacity) return false;
                }
                return false;
            }
            __builtin_prefetch(&slot, 1, 3);
            slot.data = value;
            slot.sequence.store(pos + 1, std::memory_order_release);
            producer_cache.enqueue_pos++;
            producer_cache.enqueue_count++;
            if ((producer_cache.enqueue_count & (UPDATE_THRESHOLD - 1)) == 0) [[unlikely]] shared_enqueue_pos.store(producer_cache.enqueue_pos, std::memory_order_release);
            return true;
        }
        bool dequeue(T& value) noexcept { //optimzed for P/E core
            uint64_t pos = consumer_cache.dequeue_pos;
            Slot& slot = buffer[pos & (Capacity - 1)];
            M2_PREFETCH_READ(&buffer[(pos + 1) & (Capacity - 1)]);
            //__builtin_prefetch((&buffer[(pos + 1) & (Capacity - 1)]), 1, 3);
            uint64_t seq = slot.sequence.load(std::memory_order_acquire);
            if (seq != pos + 1) [[unlikely]] { //check if slot has data
                if (pos >= consumer_cache.cached_enqueue_pos) {
                    consumer_cache.cached_enqueue_pos = shared_enqueue_pos.load(std::memory_order_acquire);
                    if (pos >= consumer_cache.cached_enqueue_pos) return false; //actual empty queue
                }
                return false;
            }
            return true;
        }
        size_t enqueue_batch(T* values, size_t count) noexcept { //batch operations alternative
            size_t enqueued = 0;
            uint64_t pos = producer_cache.enqueue_pos;
            size_t chunks = count / 4; //in chunks of 4
            size_t i = 0;
            for (size_t chunk = 0; chunk < chunks; chunk++) {
                M2_PREFETCH_WRITE(&buffer[(pos + i + 4) & (Capacity - 1)]); //prefecth 4 slots
                //__builtin_prefetch((&buffer[(pos + i + 4) & (Capacity - 1)]), 1, 3);
                for (size_t j = 0; j < 4; j++, i++) {
                    Slot& slot = buffer[(pos + i) & (Capacity - 1)];
                    uint64_t seq = slot.sequence.load(std::memory_order_acquire);
                    if (seq != pos + i) goto batch_done;
                    slot.data = std::move(values[i]);
                    slot.sequence.store(pos + i + 1, std::memory_order_release);
                    enqueued++;
                }
            }
            for (; i < count; i++) { //for remaining items
                Slot& slot = buffer[(pos + i) & (Capacity - 1)];
                uint64_t seq = slot.sequence.load(std::memory_order_acquire);
                if (seq != pos + i) break;
                slot.data = std::move(values[i]);
                slot.sequence.store(pos + i + 1, std::memory_order_release);
                enqueued++;
            }
        batch_done:
            producer_cache.enqueue_pos += enqueued;
            producer_cache.enqueue_count += enqueued;
            shared_enqueue_pos.store(producer_cache.enqueue_pos, std::memory_order_release); // Always update shared position after batch
            return enqueued;
        }
        
        size_t dequeue_batch(T* values, size_t count) noexcept {
            size_t dequeued = 0;
            uint64_t pos = consumer_cache.dequeue_pos;
            size_t chunks = count / 4; //in chunks of 4
            size_t i = 0;
            for (size_t chunk = 0; chunk < chunks; chunk++) {
                M2_PREFETCH_READ(&buffer[(pos + i + 4) & (Capacity - 1)]);
                //__builtin_prefetch((&buffer[(pos + i + 4) & (Capacity - 1)]), 1, 3);
                for (size_t j = 0; j < 4; j++, i++) {
                    Slot& slot = buffer[(pos + i) & (Capacity - 1)];
                    uint64_t seq = slot.sequence.load(std::memory_order_acquire);
                    if (seq != pos + i + 1) goto batch_done;
                    values[i] = std::move(slot.data);
                    slot.sequence.store(pos + i + Capacity, std::memory_order_release);
                    dequeued++;
                }
            }
            for (; i < count; i++) {
                Slot& slot = buffer[(pos + i) & (Capacity - 1)];
                uint64_t seq = slot.sequence.load(std::memory_order_acquire);
                if (seq != pos + i + 1) break;
                values[i] = std::move(slot.data);
                slot.sequence.store(pos + i + Capacity, std::memory_order_release);
                dequeued++;
            }
        batch_done:
            consumer_cache.dequeue_pos += dequeued;
            consumer_cache.dequeue_count += dequeued;
            shared_dequeue_pos.store(consumer_cache.dequeue_pos, std::memory_order_release);
            return dequeued;
        }
        // Check if empty (lock-free, wait-free)
        bool empty() const noexcept {
            uint64_t dequeue_pos = shared_dequeue_pos.load(std::memory_order_acquire);
            uint64_t enqueue_pos = shared_enqueue_pos.load(std::memory_order_acquire);
            return dequeue_pos >= enqueue_pos;
        }
        // Get approximate size
        size_t size() const noexcept {
            uint64_t dequeue_pos = shared_dequeue_pos.load(std::memory_order_acquire);
            uint64_t enqueue_pos = shared_enqueue_pos.load(std::memory_order_acquire);
            return enqueue_pos - dequeue_pos;
        }
        // Statistics
        uint64_t get_enqueue_count() const noexcept {
            return producer_cache.enqueue_count;
        }
        uint64_t get_dequeue_count() const noexcept {
            return consumer_cache.dequeue_count;
        }
};

namespace HDE {
    using AddressQueue = OptimizedQueue<Request, 16384>;
    using ResponderQueue = OptimizedQueue<Response, 16384>;
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
