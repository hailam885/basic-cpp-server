# basic-cpp-server

A basic C++ HTTP Server based on macOS's built-in networking API, equipped with concurrency and basic defenses against common online attacks.

Dependencies: Quill (https://github.com/odygrd/quill), and some others that i don't recall.

For downloaders: This is developed specifically for  Apple M-chips, which possesses a massive 128 byte cache line, compared to 64 bytes in most x86-64 chips. You will need to check every file, look for the macro "CACHE_LINE_SIZE", and change that variable depending on your processor's cache line size in bytes (This information is available on your chip's manufacturer's page).

Benchmark information and specs will be available in the future and it will be included here

Specs:

Apple M-2 chip (8 CPU cores, 4P / 4E cores)
Max clock speeds: 3.5 GHz / 2.8 GHz
16 GB of RAM, 100GB/s ( <- Memory bandwidth; extremely important spec)
macOS 26.1 beta

Clang 18.1.8
C++23

