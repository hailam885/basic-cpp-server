# basic-cpp-server

A basic C++ HTTP Server based on macOS's built-in networking API, equipped with concurrency and basic defenses against common online attacks.

Dependencies:
- Quill (https://github.com/odygrd/quill)
- Metal-CPP (https://developer.apple.com/metal/cpp/) (coming soon, not yet needed)

For downloaders: This is developed specifically for  Apple M-chips, which possesses a massive 128 byte cache line, compared to 64 bytes in most x86-64 chips. You will need to check every file, look for the macro "CACHE_LINE_SIZE", and change that variable depending on your processor's cache line size in bytes (This information is available on your chip's manufacturer's page). Code is mostly optimized for the M-2 chip, so any port requires major refactoring/modifications.

For port-ers who want to port this to Linux with x86-64 chips, you probably can't do this. A future update will refactor most of the codebase (particularly with the handler() function that handles client requests). There's two special things about the hardware that is present; the CPU and GPU shares the same RAM, and the massive bandwidth of 100GB/s. The massive bandwidth can be easily explained. With the older versions, the CPU handles everything, accepting connections, parsing client requests, and responding to requests. With the new Apple Silicon overhaul to Macbooks, now CPU and GPU share the same RAM, which presents an unexpected massive advantage. GPUs, with their thousands of cores, can easily handle parsing client requests that are often demanding to do and in a much larger scale than CPUs do. Originally, this requires a copy between the DRAM and VRAM, but since UMA completely blows that out, data can be shared with ZERO latency between the components. This does, however, reduces portability, as a large portion of the handler() will be written using macOS's built in Metal Graphics API.

Benchmark information and specs will be available in the future and it will be included here

Specs:
- Apple M-2 chip (8 CPU cores, 4 Performance @ 3.5GHz / 4 Efficiency cores @ 2.8GHz)
- 16 GB of RAM, 100GB/s ( <- Memory bandwidth; extremely important spec)
- macOS 26.1 release candidate (will be similar to the 26.1 release)

Additional advantages of M2:
- Support massive cache lines of 128 bytes
- Utilizes 16KB memory pages instead of the usual 2KB

Clang 18.1.8
C++23

(Benchmark will probably not coming soon since code WILL randomly SEGFAULTs and catastrophic errors are probably undetectable)

