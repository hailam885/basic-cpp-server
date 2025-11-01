#ifndef Server_hpp
#define Server_hpp
#include "SimpleServer.hpp"


//If code is commented out do not question


//#include <Foundation/Foundation.hpp>
//#include <Metal/Metal.hpp>
//#include <QuartzCore/QuartzCore.hpp>

//Fwd declare, do not question code
namespace MTL {
    class Device;
    class CommandQueue;
    class CommandBuffer;
    class CommandEncoder;
    class RenderCommandEncoder;
    class ParallelRenderCommandEncoder;
    class BlitCommandEncoder;
    class ComputeCommandEncoder;
    class AccelerationStructure;
    class AccelerationStructureCommandEncoder;
    class AccelerationStructureDescriptor;
    class PrimitiveAccelerationStructureDescriptor;
    class InstanceAccelerationStructureDescriptor;
    class Resource;
    class Buffer;
    class Texture;
    class Heap;
    class Fence;
    class Event;
    class SharedEvent;
    class SamplerState;
    class DepthStencilState;
    class RenderPipelineState;
    class ComputePipelineState;
    class TileRenderPipelineState;
    class RenderPipelineDescriptor;
    class ComputePipelineDescriptor;
    class TileRenderPipelineDescriptor;
    class RenderPassDescriptor;
    class RenderPassAttachmentDescriptor;
    class RenderPassColorAttachmentDescriptor;
    class RenderPassDepthAttachmentDescriptor;
    class RenderPassStencilAttachmentDescriptor;
    class TextureDescriptor;
    class SamplerDescriptor;
    class DepthStencilDescriptor;
    class HeapDescriptor;
    class BufferLayoutDescriptor;
    class AttributeDescriptor;
    class VertexDescriptor;
    class StencilDescriptor;
    class Library;
    class Function;
    class FunctionConstantValues;
    class FunctionDescriptor;
    class IntersectionFunctionDescriptor;
    class LinkedFunctions;
    class BinaryArchive;
    class DynamicLibrary;
    class Argument;
    class ArgumentEncoder;
    class ArgumentDescriptor;
    class VisibleFunctionTable;
    class IntersectionFunctionTable;
    class IndirectCommandBuffer;
    class IndirectCommandBufferDescriptor;
    class IndirectRenderCommand;
    class IndirectComputeCommand;
    class Counter;
    class CounterSet;
    class CounterSampleBuffer;
    class CounterSampleBufferDescriptor;
    class RasterizationRateMap;
    class RasterizationRateMapDescriptor;
    class RasterizationRateSampleArray;
    class RasterizationRateLayerDescriptor;
    class RasterizationRateLayerArray;
    class MeshRenderPipelineDescriptor;
    class ResourceStateCommandEncoder;
    class CaptureManager;
    class CaptureDescriptor;
    class CaptureScope;
    class IOCommandQueue;
    class IOCommandBuffer;
    class IOScratchBuffer;
    class IOScratchBufferAllocator;
    class IOFileHandle;
    class ResidencySet;
    class ResidencySetDescriptor;
    class Type;
    class StructType;
    class ArrayType;
    class PointerType;
    class TextureReferenceType;
    class StructMember;
    class VertexAttribute;
    class Attribute;
    class CompileOptions;
    class Architecture;
    class ArchitectureDescriptor;
    class Drawable;
    class BinaryArchiveDescriptor;
    class BufferBinding;
    class CommandQueueDescriptor;
    class ComputePipelineReflection;
    class FunctionHandle;
    class IOCommandQueueDescriptor;
    class LogState;
    class LogStateDescriptor;
    class RenderPipelineReflection;
    class ResidencySet;
    class ResourceViewPoolDescriptor;
    struct SamplePosition;
    class SharedEventHandle;
    class SharedTextureHandle;
    class StitchedLibraryDescriptor;
    class Tensor;
    class TensorDescriptor;
    class TextureViewPool;
    //struct Size;
    //struct Origin;
    //struct Region;
}

namespace MTL4 {
    class Archive;
    class ArgumentTable;
    class ArgumentTableDescriptor;
    class BinaryFunction;
    class CommandAllocator;
    class CommandAllocatorDescriptor;
    class CommandBuffer;
    class CommandQueue;
    class CommandQueueDescriptor;
    class Compiler;
    class CompilerDescriptor;
    class CounterHeap;
    class CounterHeapDescriptor;
    class PipelineDataSetSerializer;
    class PipelineDataSetSerializerDescriptor;
}

namespace NS {
    class Object;
    class String;
    class Error;
    class Array;
    class Dictionary;
    class Number;
    class Data;
    class URL;
    class Bundle;
    class ProcessInfo;
    class AutoreleasePool;
    
}

namespace CA {
    class MetalLayer;
    class MetalDrawable;
}

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
    std::string_view method;
    std::string path;
    std::string_view version;
    bool valid = false;
    std::vector<std::pair<std::string_view, std::string_view>> query_str_parsed;
};

template <typename T, size_t N>
class WaitFreeQueue;

class GPUPacketProcessor;

class M2ThreadAffinity {
public:
    // M2 has 4 P-cores (0-3) and 4 E-cores (4-7)
    enum class CoreType {
        Performance,  // High-performance cores
        Efficiency    // Energy-efficient cores
    };
    static void pin_to_p_core(int core_id) {
        if (core_id < 0 || core_id > 3) throw std::runtime_error("P-core ID must be 0-3");
        thread_affinity_policy_data_t policy = {core_id};
        thread_policy_set(pthread_mach_thread_np(pthread_self()), THREAD_AFFINITY_POLICY, reinterpret_cast<thread_policy_t>(&policy), THREAD_AFFINITY_POLICY_COUNT);
    }
    static void pin_to_e_core(int core_id) {
        if (core_id < 0 || core_id > 3) throw std::runtime_error("E-core ID must be 0-3");
        thread_affinity_policy_data_t policy = {4 + core_id};
        thread_policy_set(pthread_mach_thread_np(pthread_self()), THREAD_AFFINITY_POLICY, reinterpret_cast<thread_policy_t>(&policy), THREAD_AFFINITY_POLICY_COUNT);
    }
    // Set Quality of Service (QoS) for thread scheduling
    static void set_qos_performance() {
        pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    }
    static void set_qos_efficiency() {
        pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0);
    }
};

#pragma once
#define MS_PRIVATE_IMPLEMENTATION
#define CA_PRIVATE_IMPLEMENTATION
#define MTL_PRIVATE_IMPLEMENTATION
#include <Metal/Metal.hpp>
#include <Foundation/Foundation.hpp>
#include <cstdint>

struct GPUParsedRequest {
    unsigned int method; // 0=GET, 1=POST, 2=PUT, 3=DELETE, 4=HEAD, -1=INVALID
    unsigned int path_offset;
    unsigned int path_length;
    unsigned int version_valid;
    unsigned int content_length;
    unsigned int is_valid;
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
            static void parse_query_string(std::string_view query_string, ParsedRequest& request);
            //charset UTF-8
            static std::string_view parse_url_encoding(const std::string& url_encoded_text);
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
            inline static bool is_valid_query_string(std::string_view query_string) noexcept; 
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
        const size_t MAX_BUFFER_SIZE = 30721; //        size in bytes, recommended to be 30K+ bytes
        enum logLevel log_level = MINIMAL; //           FULL / DEFAULT / DECREASED / MINIMAL
        bool disable_logging = true; //                Fully disables logging besides the start up and config checking logs
        bool disable_warnings = false; //                Disables certain warnings
        int time_window_for_rps = 2; //                 Specifies the amount of time to count the requests to calculate instantaneous rps
        //backlog count are in a/Networking/Sockets/ListeningSocket.hpp, change the variable "backlog"

        //              [ Performance ]

        //dev notes
        //Try to improve handler function efficiency. also the write() function in responder is extremely inefficient, look for faster and less overhead alternatives to the write() function.
        //if the acceper/handler/responder's thread count is 1, delete the thread_local in the variables before the infinite loops.

        //For accepter/responder, leave 1 thread for GPU-Accelerated Handler.
        int threadsForAccepter = 3; //                  minimum 1
        int threadsForResponder = 3; //                 minimum 1
        int totalUsedThreads = threadsForAccepter + 1 + threadsForResponder; //handler defaults to 1 thread for now
        bool IO_SYNCHONIZATION = false; //              true / false                stability / performance
        int wait_before_notify_thread = 0; //           >>practically useless<<
        //int max_pos_file_size = 50; //                 possible size of the largest file in MBs, useful for certain optimizations

        //              [ Security ]

        bool enable_DoS_protection = false; //          true / false, turns on rate limiting
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
        {"/game", server_dir + "/html/path/game.html"},
        //CSS
        {"/css/index.css", server_dir + "/css/index.css"},
        {"/css/control_panel.css", server_dir + "/css/control_panel.css"},
        {"/css/path/random.css", server_dir + "/css/path/random.css"},
        {"/css/path/randoma.css", server_dir + "/css/path/randoma.css"},
        {"/css/path/resources.css", server_dir + "/css/path/resources.css"},
        {"/css/path/game.css", server_dir + "/css/path/game.css"},
        //JS
        {"/js/index.js", server_dir + "/js/index.js"},
        {"/js/control_panel.js", server_dir + "/js/control_panel.js"},
        {"/js/path/random.js", server_dir + "/js/path/random.js"},
        {"/js/path/randoma.js", server_dir + "/js/path/randoma.js"},
        {"/js/path/resources.js", server_dir + "/js/path/resources.js"},
        {"/js/path/game.js", server_dir + "/js/path/game.js"}
        //OTHERS
    };

    //DO NOT DELETE OR UNCOMMENT ANY OF THE COMMENTS THEY'RE THERE FOR A REASON

    //Performance monitoring

    class ServerMetrics {
    private:
        std::atomic<uint64_t> total_requests{0};
        std::atomic<uint64_t> successful_requests{0};
        std::atomic<uint64_t> failed_requests{0};
        std::atomic<uint64_t> bytes_received{0};
        std::atomic<uint64_t> bytes_sent{0};
        std::chrono::steady_clock::time_point start_time;
        struct TimeWindow {
            std::atomic<uint64_t> count{0};
            std::chrono::steady_clock::time_point timestamp;
        };
        static constexpr size_t WINDOW_SIZE = 10; // Track last 10 seconds
        std::array<TimeWindow, WINDOW_SIZE> request_windows;
        std::atomic<size_t> current_window{0};
        mutable uint64_t prev_cpu_total = 0;
        mutable uint64_t prev_cpu_idle = 0;
        mutable uint64_t prev_cpu_user = 0;
        mutable uint64_t prev_cpu_system = 0;
        mutable uint64_t prev_pageouts = 0;
        mutable std::chrono::steady_clock::time_point prev_measurement_time;
        mutable bool first_measurement = true;
        mutable std::mutex metrics_mutex;
    public:
        ServerMetrics() : start_time(std::chrono::steady_clock::now()) {
            auto now = std::chrono::steady_clock::now();
            for (auto& window : request_windows) {
                window.timestamp = now;
            }
        }
        void add_to_bytes_received(double num) {
            bytes_received += num;
        }
        void record_request(bool success, size_t bytes_in, size_t bytes_out);
        double get_instantaneous_rps() const;
        std::string get_metrics_json() const;
        struct CPUBreakdown {
            double user;
            double system;
            double idle;
            double total_used;
        };
    private:
        CPUBreakdown get_cpu_breakdown() const;
        double get_cpu_usage() const;
        void get_memory_usage(uint64_t& used_bytes, double& percent) const;
        uint64_t get_total_memory() const;
        int get_memory_pressure() const;  // Returns 1=normal, 2=warn, 4=critical
        struct MemoryBreakdown {
            uint64_t active;
            uint64_t wired;
            uint64_t compressed;
            uint64_t free;
            double active_percent;
            double wired_percent;
            double compressed_percent;
            double free_percent;
        };
        MemoryBreakdown get_memory_breakdown() const;
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

    class M2GPUHTTPParser {
        private:
            MTL::Device* device;
            MTL::CommandQueue* command_queue;
            MTL::ComputePipelineState* parse_pipeline;
            MTL::ComputePipelineState* validate_pipeline;
            MTL::Buffer* request_buffer;
            MTL::Buffer* parsed_buffer;
            MTL::Buffer* validation_buffer;
            //static constexpr size_t MAX_REQUEST_SIZE = 4096;
            static constexpr size_t BATCH_SIZE = 1024;
            const char* get_shader_source();
            void compile_shaders();
        public:
            M2GPUHTTPParser();
            ~M2GPUHTTPParser();
            void process_batch(const char** requests, size_t count, GPUParsedRequest* results, uint32_t* validations);
            size_t get_batch_size() const { return BATCH_SIZE; }
            size_t get_max_request_size() const { return HDE::server_config.MAX_BUFFER_SIZE; }
            MTL::Device* get_device() const { return device; }
    };

    inline std::unique_ptr<M2GPUHTTPParser> gpu_parser;

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
    inline void clean_server_shutdown(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue);
    inline void reportErrorMessage(quill::Logger* logger);
    inline bool is_rate_limited(const std::string_view client_ip);
    inline std::string_view get_thread_id_cached();

    //OS Internals
    alignas(CACHE_LINE_SIZE) inline const size_t NUM_THREADS = std::thread::hardware_concurrency();
    class Server : public SimpleServer {
        private:
            void accepter(HDE::AddressQueue& address_queue, quill::Logger* logger) override;
            void handler(HDE::AddressQueue& address_queue, HDE::ResponderQueue& responder_queue, quill::Logger* logger) override;
            void responder(HDE::ResponderQueue& response, quill::Logger* logger) override;
            //char buffer[buffer_size] = {0};
            //int new_socket;
            ResponseCache cache;
        public:
            Server(quill::Logger* logger);
            void launch(quill::Logger* logger) override;
            inline void logClientInfo(const std::string_view processing_component, const std::string_view message, quill::Logger* logger) const;
    };
}

#endif
