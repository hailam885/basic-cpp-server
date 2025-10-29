# basic-cpp-server

A basic C++ HTTP Server based on macOS's built-in networking API, equipped with concurrency and basic defenses against common online attacks.

Dependencies:
- Quill (https://github.com/odygrd/quill)
- Metal-CPP (https://developer.apple.com/metal/cpp/) (coming soon, not yet needed)

For downloaders: This is developed specifically for  Apple M-chips, which possesses a massive 128 byte cache line, compared to 64 bytes in most x86-64 chips. You will need to check every file, look for the macro "CACHE_LINE_SIZE", and change that variable depending on your processor's cache line size in bytes (This information is available on your chip's manufacturer's page). Code is mostly optimized for the M-2 chip, so any port requires major refactoring/modifications.

For port-ers who want to port this to Linux with x86-64 chips, give up. A future overhaul commit will change everything. Since M2 utilizes Unified Memory Architecture (CPU and GPU share the same RAM), there's no latency between sharing with the two components. With the old version, only ~5-6 requests can be processed at a time (corresponding to the allocation of threads). However, with GPUs, thousands of requests can be processed in a true parallel manner. Most of the work will be handled by the GPU via macOS's Metal API, and the rest of the cores will be for accepting/responding with connections (say 4 for accepter() and 4 for responder())

Benchmark information and specs will be available in the future and it will be included here

Specs:
- Apple M-2 chip (8 CPU cores, 4 Performance @ 3.5GHz / 4 Efficiency cores @ 2.8GHz)
- 16 GB of RAM, 100GB/s ( <- Memory bandwidth; extremely important spec)
- UMA, CPU/GPU shares the same RAM
- macOS 26.1 release candidate (will be similar to the 26.1 release)

Additional advantages of M2:
- Support massive cache lines of 128 bytes
- Utilizes 16KB memory pages instead of the usual 2KB

Clang 18.1.8
C++23

(Benchmark will probably not coming soon since code WILL randomly SEGFAULTs and catastrophic errors are probably undetectable)

