# basic-cpp-server

A basic C++ HTTP Server based on macOS's built-in networking API, equipped with concurrency and basic defenses against common online attacks such as buffer overflow or DoS (by rate-limiting).

You can configure the server in the file Server.hpp in a/Networking/Servers/Server.hpp, scrolling to about the middle of the file where struct serverConfig is defined.

Dependencies:
- Quill 10.2.0 Stable (https://github.com/odygrd/quill)
- Metal-CPP for macOS 26 (https://developer.apple.com/metal/cpp/) (coming soon, not yet needed)

This can be easily ported to Linux, as macOS and Linux is built based on Unix and shares many similarities in terms of software; however, the codebase (in a future update) will be tailored to Apple Silicon chips specifically and thus not easily portable. Due to the hidden advantages of Unified Memory Architecture (found in Apple Silicon chips specifically), most of the heavy work of parsing client requests and building responses will be offloaded to the GPU, and all will be powered with macOS's built-in Metal Graphics API. If you want you want to port this, you can use Vulkan or OpenGL, but it will require additional work/modifications.

Benchmark information and specs will be available in the future and it will be included here

Specs:
- Apple M-2 chip (8 cores, 4 Performance @ 3.5GHz + 4 Efficiency @ 2.8GHz)
- 16 GB of RAM, 100GB/s bandwidth
- macOS 26.1 release candidate (will be similar to the macOS 26.1 release)

Additional advantages of M2:
- Support massive cache lines of 128 bytes
- Utilizes 16KB memory pages instead of the usual 2KB

Clang 18.1.8 with C++23

(Benchmark will probably not coming soon since code WILL randomly SEGFAULTs and catastrophic errors are probably undetectable, and also GPU-Accelerated request parsing is causing major refactoring to the codebase so it's probably going to be a while)



(Optional: Updates)

[10/30/2025]: Just now thought that GPUs can do most of the request parsing work. Probably take until 2026 for the code to be stable