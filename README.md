# moonprot v2
single-header x64 windows string + function pointer encryption  
lightweight · zero deps · p2c-grade but actually good

### why
Most public "xor string" libs are detected in 2 seconds.  
This one uses:
- 4-stage per-byte encryption
- per-instance compile-time salts (every string has different keys)
- encrypted function pointers (`enc_fn`)
- auto wipe + cache flush
- decoy guard pages
- control-flow junk
- everything `__forceinline` on MSVC

Still < 2 KB compiled. Still single header.

### usage

```cpp
#include "moonprot.h"

static auto enc_msgbox = moonprot::enc_fn(&MessageBoxA);

int main() {
    moonprot::init(); // optional anti-dump noise

    moon_xor("this string never exists in plaintext on disk")
        .use([](const char* s) {
            enc_msgbox(0, s, moon_xor("cap").decrypt(), MB_OK);
        });
}
```

### features

| feature                     | enabled by default |
|----------------------------|-------------------|
| 4-stage string encryption   | yes               |
| per-string random salt      | yes               |
| encrypted function pointers | yes               |
| auto memory wipe + clflush  | yes               |
| guard-page decoys           | yes               |
| junk control flow           | yes               |

### config (change in moonprot.h)

```c++
namespace moonprot::config {
    constexpr bool enable_auto_wipe   = true;
    constexpr bool enable_page_guard  = true;
    constexpr bool enable_decoy_alloc = true;
    constexpr bool enable_cf_flatten  = true;

    // change these four keys per project
    constexpr uint64_t key1 = 0xA9F23C8D9911AE77ULL;
    constexpr uint64_t key2 = 0xC6EF3720B5D1E9A3ULL;
    constexpr uint64_t key3 = 0x1F123BB5DEADBEEFULL;
    constexpr uint64_t key4 = 0x8E5D4C3B2A1907F6ULL;
}
```

### macros

- `moon_xor("hello")` → encrypted string
- `moonprot::enc_fn(&SomeApi)` → encrypted callable wrapper

### tested on
- MSVC 2022 (x64)
- Works in cheats, loaders, manual-maps, anything

Drop `moonprot.h`, change the four keys, profit.

Enjoy. This was originally going to be a private release <3.