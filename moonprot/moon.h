#pragma once
#include <windows.h>
#include <cstdint>
#include <type_traits>
#include <array>
#include <cstring>
#include <intrin.h>

namespace moonprot
{
    namespace config
    {
        constexpr bool enable_auto_wipe = true;
        constexpr bool enable_page_guard = true;
        constexpr bool enable_decoy_alloc = true;
        constexpr bool enable_cf_flatten = true;

        // change these per project — they are baked into every encrypted string
        constexpr std::uint64_t key1 = 0xA9F23C8D9911AE77ULL;
        constexpr std::uint64_t key2 = 0xC6EF3720B5D1E9A3ULL;
        constexpr std::uint64_t key3 = 0x1F123BB5DEADBEEFULL;
        constexpr std::uint64_t key4 = 0x8E5D4C3B2A1907F6ULL;
    }

    // compile-time prng for per-instance salts (splitmix64)
    constexpr std::uint64_t splitmix64(std::uint64_t& s)
    {
        std::uint64_t z = (s += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }

    // each xor_string gets its own unique salt at compile time
    template<std::size_t N>
    constexpr std::uint64_t instance_salt()
    {
        std::uint64_t s = N ^ config::key4;
        splitmix64(s); splitmix64(s);
        return s;
    }

    // position-dependent key stream — 4 master keys + salt + index
    constexpr std::uint8_t derive_key(std::size_t i, std::uint64_t salt)
    {
        std::uint64_t a = config::key1 ^ salt;
        std::uint64_t b = config::key2 + i;
        std::uint64_t c = config::key3 ^ (i << 13 | i >> 51);

        std::uint64_t k = a ^ (a << 11 | a >> 53);
        k += b;
        k = (k << 17 | k >> 47);
        k ^= c;
        k = (k << 29 | k >> 35);
        k += config::key4;

        return static_cast<std::uint8_t>(k >> ((i & 7) << 3));
    }

    template<std::size_t N>
    class xor_string
    {
        alignas(16) std::array<std::uint8_t, N> data{};
        const std::uint64_t salt = instance_salt<N>();

        // 4-stage reversible encryption at compile time
        constexpr void encrypt(const char(&s)[N])
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                std::uint8_t k = derive_key(i, salt);
                std::uint8_t v = static_cast<std::uint8_t>(s[i]);

                v ^= k;                               // stage 1
                v += (k >> 4) + static_cast<std::uint8_t>(i); // stage 2 (position aware)
                v = (v << 3) | (v >> 5);               // stage 3 (rotate 3)
                v ^= k + 0x42;                         // stage 4

                data[i] = v;
            }
        }

        // matching runtime decryption
        __forceinline void decrypt_internal()
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                std::uint8_t k = derive_key(i, salt);
                std::uint8_t v = data[i];

                v ^= k + 0x42;
                v = (v >> 3) | (v << 5);
                v -= (k >> 4) + static_cast<std::uint8_t>(i);
                v ^= k;

                data[i] = v;
            }
        }

    public:
        constexpr xor_string(const char(&s)[N]) { encrypt(s); }

        __forceinline char* decrypt()
        {
            decrypt_internal();
            return reinterpret_cast<char*>(data.data());
        }

        // secure wipe + cache line flush (helps against cold-boot / memory dumping)
        __forceinline void wipe() noexcept
        {
            if constexpr (config::enable_auto_wipe)
            {
                volatile std::uint8_t* p = data.data();
                for (std::size_t i = 0; i < N; ++i) p[i] = 0;

                for (std::size_t i = 0; i < N; i += 64)
                    _mm_clflush(&data[i]);

                _ReadWriteBarrier();
            }
        }

        // main usage pattern — decrypt → use → wipe automatically + optional junk CF
        template<typename F>
        __forceinline auto use(F&& f)
        {
            char* ptr = decrypt();

            if constexpr (config::enable_cf_flatten)
            {
                int state = 0xDEAD;
                void* junk[4]{};
                switch (state ^ 0xBEEF)
                {
                case 0xDEAD ^ 0xBEEF:
                    goto real;
                default:
                    junk[1] = nullptr; // never taken
                }
            real:
                auto res = f(ptr);
                wipe();
                return res;
            }
            else
            {
                auto res = f(ptr);
                wipe();
                return res;
            }
        }
    };

#define moon_xor(str) moonprot::xor_string<sizeof(str)>(str)

    // encrypted function pointer — hides real address in .rdata
    template<typename Ret = void, typename... Args>
    struct enc_fn
    {
        alignas(16) std::uint64_t blob[4]{};

        constexpr enc_fn() = default;
        constexpr enc_fn(Ret(*f)(Args...))
        {
            std::uint64_t raw = reinterpret_cast<std::uint64_t>(f);
            std::uint64_t k = config::key1 ^ config::key3;

            for (int i = 0; i < 4; ++i)
            {
                std::uint64_t v = (raw >> (i * 16)) & 0xFFFF;
                v ^= (k >> (i * 11)) & 0xFFFF;
                v = (v << 7) | (v >> 9);
                blob[i] = v;
            }
        }

        __forceinline Ret operator()(Args... a) const
        {
            std::uint64_t k = config::key1 ^ config::key3;
            std::uint64_t raw = 0;

            for (int i = 3; i >= 0; --i)
            {
                std::uint64_t v = blob[i];
                v = (v >> 7) | (v << 9);
                v ^= (k >> (i * 11)) & 0xFFFF;
                raw = (raw << 16) | v;
            }

            using fn_t = Ret(*)(Args...);
            return reinterpret_cast<fn_t>(raw)(a...);
        }
    };

    template<typename F, typename... A>
    __forceinline auto enc_call(F f, A... a) { return f(a...); }

    // runtime init — creates noise pages that trigger exceptions on scan/dump
    __forceinline void init()
    {
        if constexpr (config::enable_decoy_alloc)
        {
            for (int i = 0; i < 8; ++i)
            {
                SIZE_T sz = 0x1000 << (i % 4);
                void* p = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
                if (p && config::enable_page_guard)
                {
                    DWORD old;
                    VirtualProtect(p, 0x1000, PAGE_READWRITE | PAGE_GUARD, &old);
                }
            }
        }

        // burn cycles + touch keys to defeat simple static key extraction
        volatile std::uint64_t x = config::key1 ^ config::key2;
        for (int i = 0; i < 128; ++i)
            x = (x << 11) ^ (x >> 19) ^ config::key4;
        (void)x;
    }

} // namespace moonprot