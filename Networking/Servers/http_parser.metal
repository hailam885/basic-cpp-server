#include <metal_stdlib>
using namespace metal;

// Use packed structure (no padding)
struct ParsedRequest {
    uint method;
    uint path_offset;
    uint path_length;
    uint version_valid;
    uint content_length;
    uint is_valid;
} __attribute__((packed));

inline bool compare_4(const device char* str, char4 literal) {
    char4 data = *((device char4*)str); // load 4 bytes at once
    return all(data == literal);
}

inline bool compare_8(const device char* str, const char* literal) {
    ulong data = *((device ulong*)str); // load 8 bytes at once
    ulong lit = *((constant ulong*)literal);
    return data == lit;
}

kernel void parse_http_requests_optimized(
    device const char* requests [[buffer(0)]],
    device ParsedRequest* results [[buffer(1)]],
    constant uint& request_size [[buffer(2)]],
    uint tid [[thread_position_in_grid]],
    uint lid [[thread_position_in_threadgroup]],
    uint gid [[threadgroup_position_in_grid]]])
    {
        device const char* req = requests + (tid * request_size);
        device ParsedRequest& result = results[tid];
        device const char* prefetch_addr = req + 128;
        result.method = 0xFFFFFFFF; //optimized to vector ops
        result.path_offset = 0;
        result.path_length = 0;
        result.version_valid = 0;
        result.content_length = 0;
        result.is_valid = 0;
        char4 first_4 = *((device char4*)req);
        if (all(first_4 == char4('G', 'E', 'T', ' '))) { //vectorized compare
            result.method = 0;
        } else if (compare_4(req, char4('P', 'O', 'S', 'T'))) {
            if (req[4] == ' ') result.method = 1;
        } else if (compare_4(req, char4('P', 'U', 'T', ' '))) {
            result.method = 2;
        } else if (compare_8(req, "DELETE ")) {
            result.method = 3;
        } else if (compare_4(req, char4('H', 'E', 'A', 'D'))) {
            if (req[4] == ' ') result.method = 4;
        } else {
            return;  // invalid method
        }
        uint i = (result.method == 1 || result.method == 3) ? ((result.method == 1) ? 5 : 7) : 4; // find path (optimized loop unrolling)
        uint path_start = i;
        #pragma unroll 4
        while (i < request_size - 4) { //process 4 char per iteration
            char4 chunk = *((device char4*)(req + i));
            if (any(chunk == ' ' || chunk == '?' || chunk == '\r')) {
                for (uint j = 0; j < 4; j++) { // Find exact position
                    if (req[i + j] == ' ' || req[i + j] == '?' || req[i + j] == '\r') {
                        i += j;
                        goto path_end;
                    }
                }
            }
            i += 4;
        }
    path_end:
        result.path_offset = path_start;
        result.path_length = i - path_start;
        while (i < request_size && req[i] != 'H') i++;
        if (i + 8 <= request_size) {
            ulong version = *((device ulong*)(req + i));
            constant ulong http11 = 0x312E312F50545448;  // "HTTP/1.1" in hex
            constant ulong http10 = 0x302E312F50545448;  // "HTTP/1.0" in hex
            if (version == http11 || version == http10) result.version_valid = 1;
        }
        result.is_valid = (result.method != 0xFFFFFFFF && result.version_valid == 1) ? 1 : 0;
    }