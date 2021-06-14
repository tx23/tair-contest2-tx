#ifndef TAIR_CONTEST_KV_CONTEST_NVM_UTIL_H_
#define TAIR_CONTEST_KV_CONTEST_NVM_UTIL_H_

#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <cstdio>
#include <string>
#include <chrono>
#include <sys/time.h>
#include <pthread.h>
#include <atomic>
#include <unistd.h>
#include "Config.hpp"

FILE *g_log_file = nullptr;

#define CAS(ptr, _old, _new) __sync_bool_compare_and_swap(ptr, _old, _new)//CAS原子操作

class spin_mutex {
    std::atomic_flag flag = ATOMIC_FLAG_INIT;
public:
    spin_mutex() = default;

    spin_mutex(const spin_mutex &) = delete;

    spin_mutex &operator=(const spin_mutex &) = delete;

    void lock() {
        while (flag.test_and_set(std::memory_order_acquire));
    }

    void unlock() {
        flag.clear(std::memory_order_release);
    }
};

inline int align16(int size) { //16字节对齐
    int t = size & 15;
    if (t == 0 ) { //16的倍数
        return size;
    }

    return size - t + 16;
}

inline int align8(int size) { //8字节对齐
    int t = size & 7;
    if (t == 0 ) { //16的倍数
        return size;
    }

    return size - t + 8;
}

inline int relative_offset(long offset) {
    return (int)(offset >> 3);
}

inline long real_offset(uint32_t offset) {
    return ((long)offset) << 3;
}

inline char relative_offset_char(int offset) {
    return (char)(offset >> 3);
}

inline int real_offset_char(int offset) {
    return offset << 3;
}

inline int NvmEngine::_hash(char *str) {
    return *(reinterpret_cast<uint64_t *>(str)) & INDEX_MASK;
}

//缓存行大小64字节
struct Counter{
    long p01, p02;
    long p11, p11;
    long cnt;
    long p21;
    long p31, p32;
};

#endif