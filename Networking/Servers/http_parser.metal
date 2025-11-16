#include <metal_stdlib>
using namespace metal;

struct GPUParsedRequest {
    unsigned int method;         // 0=GET, 1=POST, 2=PUT, 3=HEAD, 4=INVALID
    unsigned int path_offset;    // Byte offset where path starts in request
    unsigned int path_length;    // Length of path in bytes
    unsigned int version_valid;  // HTTP 1.0/1.1
    //unsigned int content_length;
    unsigned int is_valid;       // 1=valid request line, 0=invalid
};

/**
 * parses HTTP request line to extract method and path location
 * format: "GET /path HTTP/1.1\r\n"
 *         "POST /api/data HTTP/1.1\r\n"
 * 
 * @param requests - Raw HTTP request text (concatenated array)
 * @param results - Output: parsed request information
 * @param max_request_size - Size allocated for each request
 * @param gid - Global thread ID (which request this thread handles)
 */

//

 //parameters: input buffer, output buffer, constant, thread id grid
kernel void parse_http_requests(device const uchar* requests [[buffer(0)]], device GPUParsedRequest* results [[buffer(1)]], constant uint& max_request_size [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    device const uchar* request = requests + (gid * max_request_size); //y = mx + b;
    //assume invalid until proven valid
    results[gid].method = 4;
    results[gid].path_offset = 0;
    results[gid].path_length = 0;
    results[gid].is_valid = 0;
    if (request[0] == 'G' && request[1] == 'E' && request[2] == 'T') {
        results[gid].method = 0;          // 0 = GET
        results[gid].path_offset = 4;     // Path starts after "GET "
    } else if (request[0] == 'P' && request[1] == 'O' && request[2] == 'S' && request[3] == 'T') {
        results[gid].method = 1;          // 1 = POST
        results[gid].path_offset = 5;     // Path starts after "POST "
    } else if (request[0] == 'P' && request[1] == 'U' && request[2] == 'T') {
        results[gid].method = 2;          // 2 = PUT
        results[gid].path_offset = 4;     // Path starts after "PUT "
    } else if (request[0] == 'H' && request[1] == 'E' && request[2] == 'A' && request[3] == 'D') {
        results[gid].method = 3;          // 3 = HEAD
        results[gid].path_offset = 5;     // Path starts after "HEAD "
    } else {
        return; //unknown method, leave as unknown/4 and return
    }
    uint path_start = results[gid].path_offset;
    uint path_end = path_start;
    // scan forward looking for space, carriage return, or newline
    for (uint i = path_start; i < max_request_size; i++) {
        uchar c = request[i];
        if (c == ' ' || c == '\r' || c == '\n') { //end of path
            path_end = i;
            break;
        }
        if (c == 0) { //null terminator -> end of path
            path_end = i;
            break;
        }
    }
    //valid path validation
    if (path_end > path_start) {
        // Valid path found
        results[gid].path_length = path_end - path_start;
        results[gid].is_valid = 1;
        if (results[gid].path_length > 2048) {
            results[gid].is_valid = 0;  // Suspiciously long path
        }
    } else {
        results[gid].is_valid = 0; // No valid path found (path_end <= path_start)
    }
    //HTTP version validation
    uint loc = results[gid].path_offset + results[gid].path_length + 1;
    if ((request[loc] == 'H' && request[loc + 1] == 'T' && request[loc + 2] == 'T' && request[loc + 3] == 'P' && request[loc + 4] == '/' && request[loc + 5] == '1' && request[loc + 6] == '.' && request[loc + 7] == '1') || (request[loc] == 'H' && request[loc + 1] == 'T' && request[loc + 2] == 'T' && request[loc + 3] == 'P' && request[loc + 4] == '/' && request[loc + 5] == '1' && request[loc + 6] == '.' && request[loc + 7] == '0')) {
        results[gid].version_valid = 1;
    } else {
        results[gid].version_valid = 0;
        if (results[gid].is_valid == 1) {
            results[gid].is_valid = 0;
        }
    }
    // thread is done - result is written to global memory, metal automatically ensures writes are visible to CPU
}
/**
 * @param requests - Raw HTTP request text
 * @param parsed - Parsed request data from previous kernel
 * @param validation_results - Output: 1=valid, 0=invalid
 * @param max_request_size - Size allocated for each request
 * @param gid - Global thread ID
 */
 //validates url paths for security vulnerabilities
 //each thread validates one request's path
kernel void validate_urls(device const uchar* requests [[buffer(0)]], device const GPUParsedRequest* parsed [[buffer(1)]], device uint* validation_results [[buffer(2)]], constant uint& max_request_size [[buffer(3)]], uint gid [[thread_position_in_grid]]) {
    validation_results[gid] = 0;  // assume invalid
    if (parsed[gid].is_valid == 0) return; //path already invalid, no need to check
    //path info
    uint path_offset = parsed[gid].path_offset;
    uint path_length = parsed[gid].path_length;
    //sanity check
    if (path_length == 0) return; //empty path is invalid
    //get pointer to the path within this request
    device const uchar* request = requests + (gid * max_request_size);
    device const uchar* path = request + path_offset;
    //check: direct traversal attack
    for (uint i = 0; i < path_length - 1; i++) {
        if (path[i] == '.' && path[i + 1] == '.') {
            return;  // invalid: contains ".." -> path traversal
        }
    }
    //check: null byte injection, can terminate strings in some parsers
    for (uint i = 0; i < path_length; i++) {
        if (path[i] == 0) {
            return;  // invalid: contains null byte (injection attack)
        }
    }
    //check: valid url characters only
    for (uint i = 0; i < path_length; i++) {
        uchar c = path[i];
        bool is_lowercase_letter = (c >= 'a' && c <= 'z');
        bool is_uppercase_letter = (c >= 'A' && c <= 'Z');
        bool is_digit = (c >= '0' && c <= '9');
        bool is_slash = (c == '/');
        bool is_dash = (c == '-');
        bool is_underscore = (c == '_');
        bool is_dot = (c == '.');
        bool is_valid_char = is_lowercase_letter || is_uppercase_letter || is_digit || is_slash || is_dash || is_underscore || is_dot;
        if (!is_valid_char) {
            return;  // invalid: contains forbidden character
        }
    }
    //check: path must start with /
    if (path[0] != '/') {
        return;  // invalid: path must starts with /
    }
    validation_results[gid] = 1;
}