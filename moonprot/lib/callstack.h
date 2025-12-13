#pragma once
#include <windows.h>
#include <utility>
#include <intrin.h>
#include <iostream>
#include "../helpers.h"

inline constexpr int max_func_buffered = 100;
inline constexpr int shellcode_generator_size = 500;

namespace moonprot
{
    class callstack
    {
        class spoof_function
        {
        public:
            uintptr_t temp{};
            void* ret_addr_in_stack{};

            explicit spoof_function(void* addr) : ret_addr_in_stack(addr)
            {
                temp = *reinterpret_cast<uintptr_t*>(ret_addr_in_stack);
                temp ^= SECURITY_KEY;
                *reinterpret_cast<uintptr_t*>(ret_addr_in_stack) = 0;
            }

            ~spoof_function()
            {
                temp ^= SECURITY_KEY;
                *reinterpret_cast<uintptr_t*>(ret_addr_in_stack) = temp;
            }
        };

        __forceinline static uintptr_t locate_shellcode(void* func, size_t size = shellcode_generator_size)
        {
            void* addr = VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!addr)
                return 0;

            memcpy(addr, func, size);
            return reinterpret_cast<uintptr_t>(addr);
        }

        template <typename func_t, typename... args_t>
        __declspec(safebuffers)
            static typename std::invoke_result<func_t, args_t...>::type
            shellcode_generator(func_t f, args_t&... args)
        {
            using return_type = typename std::invoke_result<func_t, args_t...>::type;

            void* ret_addr = _AddressOfReturnAddress();
            uintptr_t temp = *reinterpret_cast<uintptr_t*>(ret_addr);
            temp ^= SECURITY_KEY;
            *reinterpret_cast<uintptr_t*>(ret_addr) = 0;

            if constexpr (std::is_same_v<return_type, void>)
            {
                f(args...);
                temp ^= SECURITY_KEY;
                *reinterpret_cast<uintptr_t*>(ret_addr) = temp;
            }
            else
            {
                return_type ret = f(args...);
                temp ^= SECURITY_KEY;
                *reinterpret_cast<uintptr_t*>(ret_addr) = temp;
                return ret;
            }
        }

        template <class func_t>
        class safe_call
        {
            func_t* func_ptr{};

        public:
            explicit safe_call(func_t* func) : func_ptr(func) {}

            template <typename... args_t>
            __forceinline decltype(auto) operator()(args_t&&... args)
            {
                spoof_function _spoof(_AddressOfReturnAddress());

                using generator_t = decltype(&shellcode_generator<func_t*, args_t...>);
                generator_t self_addr =
                    reinterpret_cast<generator_t>(&shellcode_generator<func_t*, args_t&&...>);

                static size_t count{};
                static generator_t orig_generator[max_func_buffered]{};
                static uintptr_t alloc_generator[max_func_buffered]{};

                generator_t shellcode = nullptr;

                for (size_t i = 0; i < count; ++i)
                {
                    if (orig_generator[i] == self_addr)
                    {
                        shellcode = reinterpret_cast<generator_t>(alloc_generator[i]);
                        break;
                    }
                }

                if (!shellcode)
                {
                    uintptr_t shell_addr =
                        locate_shellcode(reinterpret_cast<void*>(self_addr));

                    if (!shell_addr || count >= max_func_buffered)
                        return decltype(shellcode(func_ptr, args...))();

                    orig_generator[count] = self_addr;
                    alloc_generator[count] = shell_addr;

                    shellcode = reinterpret_cast<generator_t>(shell_addr);
                    ++count;
                }

                return shellcode(func_ptr, args...);
            }
        };

    public:
        __forceinline static spoof_function spoof_func()
        {
            return spoof_function(_AddressOfReturnAddress());
        }

        template <typename func_t>
        __forceinline static safe_call<func_t> spoof_call(func_t* fn)
        {
            return safe_call<func_t>(fn);
        }
    };
}
