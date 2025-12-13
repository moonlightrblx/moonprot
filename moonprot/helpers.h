#pragma once

#define SECURITY_KEY 0x86768653 // security key used for all encryption / decryption in moonprot

#ifdef _MSC_VER
#define SECTION(x) __declspec(allocate(x))
#else
#define SECTION(x) __attribute__((section(x)))
#endif
#define FAKE_SIG(name, section, sig) \
    SECTION(section) static char * name = (char*)sig;


#ifdef _MSC_VER

#pragma section(".hidden", execute, read, write)

// all these really do is just create a really nice custom section that makes it really weird to RE.
// idk if this works with compiler optimizations at all.
// i really suck at shit that has to do with the compiler so i usually js turn everything default <3

#define MOON_START_PROTECT __pragma(code_seg(push, ".hidden"))
#define MOON_END_PROTECT   __pragma(code_seg(pop))

#else
#define MOON_START_PROTECT
#define MOON_END_PROTECT
#endif

#define prot_func __forceinline static