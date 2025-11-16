#include "Server.hpp"


//If code is commented out do not question


int main() {
    quill::Backend::start();
    auto console_sink = quill::Frontend::create_or_get_sink<quill::ConsoleSink>("sink_id_1");
    quill::Logger* logger = quill::Frontend::create_or_get_logger("root", std::move(console_sink));
    logger -> set_log_level(quill::LogLevel::TraceL3);
    HDE::Server obj = HDE::Server(logger);
}
/* Commands list:

NOTICE:

-flto: =thin is for development, =full is final releases
-fstrict-aliasing: only if you cast pointers correctly
-fomit-frame-pointer: No X29 register, faster, but not goot for sanitize address

BENMARKING ONLY:

-mbranch-protection=standard (secure) -mbranch-protection=none (fast)
-ffast-math: aggressive floating point optimizations, BRICKS IEEE754 (benchmark only)
-fno-exceptions -fno-rtti: disable C++ runtime overhead (benchmark only)
-fno-stack-protector: no stack canaries (benchmark only)
-fsanitize-memory-track-origin: trace origin of memory errors, either set to 1 or 2, mostly in-dev only, not prod

/usr/bin/clang++ -Wpedantic -ferror-limit=0 -std=c++23 -stdlib=libc++ -fcolor-diagnostics -fansi-escape-codes -fexperimental-library -I/Users/trangtran/Desktop/coding_files/a/Networking/Servers/metal-cpp -fsanitize=address -fsanitize-memory-track-origins=2 -fsanitize-memory-use-after-dtor -fsanitize=undefined -march=armv8.6-a+lse+rcpc -mtune=apple-m2 -flto=thin -fvectorize -funroll-loops -falign-functions=32 -falign-loops=32 -fstrict-aliasing -fstack-protector-strong -mbranch-protection=standard -D_FORTIFY_SOURCE=2 -DNDEBUG -O3 -g3 /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp -DNS_PRIVATE_IMPLEMENTATION -DMTL_PRIVATE_IMPLEMENTATION -DCA_PRIVATE_IMPLEMENTATION -framework Metal -framework Foundation -framework QuartzCore -mmacos-version-min=15.2 /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main



Executing:

./a/networking/Servers/main

Deleting:

sudo rm -rf a/Networking/Servers/main

- How to use PGO (Final builds only):

Compiling w/ Profile-Guided w/ -03 argument:

/usr/bin/clang++ -std=gnu++14 -Wpedantic -ferror-limit=0 -std=c++23 -O3 -march=native -fcolor-diagnostics -fansi-escape-codes -fexperimental-library -I/Users/trangtran/Desktop/coding_files/a/Networking/Servers/metal-cpp -DNS_PRIVATE_IMPLEMENTATION -DCA_PRIVATE_IMPLEMENTATION -DMTL_PRIVATE_IMPLEMENTATION -framework Metal -framework Foundation -framework QuartzCore -fsanitize=address -g -fprofile-instr-generate /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/mtl_implementation.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main

./a/Networking/Servers/main

(Basic testing command, can use either ab/wrk)
ab -n 100000 -c 18000 http://192.168.12.109:80/

llvm-profdata merge -output=default.profdata default.profraw

/usr/bin/clang++ -std=gnu++14 -Wpedantic -ferror-limit=0 -std=c++23 -O3 -march=native -fcolor-diagnostics -fansi-escape-codes -fexperimental-library -I/Users/trangtran/Desktop/coding_files/a/Networking/Servers/metal-cpp -DNS_PRIVATE_IMPLEMENTATION -DCA_PRIVATE_IMPLEMENTATION -DMTL_PRIVATE_IMPLEMENTATION -framework Metal -framework Foundation -framework QuartzCore -fsanitize=address -g -fprofile-instr-use=default.profraw /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/mtl_implementation.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/Server.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Servers/SimpleServer.cpp /Users/trangtran/Desktop/coding_files/a/Networking/hdelibc-networking.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/BindingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ConnectingSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/hdelibc-sockets.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/ListeningSocket.cpp /Users/trangtran/Desktop/coding_files/a/Networking/Sockets/SimpleSocket.cpp -o /Users/trangtran/Desktop/coding_files/a/Networking/Servers/main_pgo

./a/Networking/Servers/main_pgo

*/


/*

# 1. Quick sanity check
ab -n 1000000 -c 250 http://192.168.12.109:80/

# 2. Real-world simulation (100 concurrent users)
wrk -t6 -c100 -d30s http://192.168.12.109:80/

# 3. Find maximum throughput
wrk -t8 -c1000 -d60s http://192.168.12.109:80/

# 4. Latency test at specific rate
wrk2 -t6 -c100 -d30s -R10000 http://192.168.12.109:80/

# 5. Extended soak test (find memory leaks)
wrk -t8 -c200 -d300s http://192.168.12.109:80/

*/


/*
Some initial benchmarks (outdated):
trangtran@Mac ~ % ab -n 1000000 -c 250 http://192.168.12.109:80/ && wrk -t6 -c500 -d30s http://192.168.12.109:80/ && wrk -t8 -c1000 -d60s http://192.168.12.109:80/ && wrk -t8 -c200 -d300s http://192.168.12.109:80/
This is ApacheBench, Version 2.3 <$Revision: 1913912 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 192.168.12.109 (be patient)
Completed 100000 requests
Completed 200000 requests
Completed 300000 requests
Completed 400000 requests
Completed 500000 requests
Completed 600000 requests
Completed 700000 requests
Completed 800000 requests
Completed 900000 requests
Completed 1000000 requests
Finished 1000000 requests


Server Software:        
Server Hostname:        192.168.12.109
Server Port:            80

Document Path:          /
Document Length:        8437 bytes

Concurrency Level:      250
Time taken for tests:   48.878 seconds
Complete requests:      1000000
Failed requests:        0
Total transferred:      8574000000 bytes
HTML transferred:       8437000000 bytes
Requests per second:    20459.13 [#/sec] (mean)
Time per request:       12.219 [ms] (mean)
Time per request:       0.049 [ms] (mean, across all concurrent requests)
Transfer rate:          171305.29 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    8  66.0      4    4007
Processing:     1    4  15.4      4    1023
Waiting:        0    4  15.4      4    1023
Total:          4   12  67.8      8    4010

Percentage of the requests served within a certain time (ms)
  50%      8
  66%      8
  75%      9
  80%      9
  90%      9
  95%     10
  98%     11
  99%     13
 100%   4010 (longest request)
Running 30s test @ http://192.168.12.109:80/
  6 threads and 500 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     8.75ms   47.99ms 917.75ms   98.91%
    Req/Sec     2.87k     0.90k    4.41k    78.42%
  315198 requests in 30.10s, 2.52GB read
  Socket errors: connect 498, read 0, write 0, timeout 0
Requests/sec:  10473.26
Transfer/sec:     85.64MB
Running 1m test @ http://192.168.12.109:80/
  8 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   176.13us    2.70ms   1.00s    99.91%
    Req/Sec     6.67k     3.47k    9.52k    68.65%
  481827 requests in 1.00m, 3.85GB read
  Socket errors: connect 999, read 0, write 0, timeout 0
Requests/sec:   8020.22
Transfer/sec:     65.58MB
Running 5m test @ http://192.168.12.109:80/
  8 threads and 200 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     5.18ms   62.27ms   1.48s    99.27%
    Req/Sec     6.54k     3.39k   10.55k    63.97%
  2588441 requests in 5.00m, 20.67GB read
  Socket errors: connect 199, read 0, write 0, timeout 0
Requests/sec:   8625.57
Transfer/sec:     70.53MB
*/