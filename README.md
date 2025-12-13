# moonprot

**single-header · x64 Windows · protection / obfuscation library**
lightweight · zero runtime dependencies

---

## overview

moonprot is a Windows-native protection library focused on **runtime opacity**, not cosmetic obfuscation.

It is designed for:

* internals
* externals
* manual-mapped modules
* loaders
* protected usermode components

moonprot avoids plaintext, static callsites, and predictable patterns.

---

## core goals

* no plaintext strings in `.rdata`
* no direct API callsites in `.text`
* hidden execution paths
* spoofed callstacks
* runtime-only decryption
* manual memory wipe support

---

## features

| feature                       | status  |
| ----------------------------- | ------- |
| encrypted strings (XOR)       | working |
| rolling per-string keys       | working |
| runtime decrypt only          | working |
| manual memory wipe (`clear`)  | working |
| encrypted API calls           | working |
| callstack spoofing            | working |
| shellcode execution           | working |
| hidden code section execution | working |
| protection helpers            | working |

---

## basic usage

```cpp
#include "moonprot/includes.h"

int main()
{
    MOON_START_PROTECT

    moonprot::prot::init();

    auto secret = _cat("login_token_123");
    printf("%s\n", secret.decrypt());
    secret.clear();

    moonprot::callstack::spoof_call(&MessageBoxA)(
        nullptr,
        "hi",
        "moonprot",
        MB_OK
    );

    MOON_END_PROTECT
}
```

---

## macros

### code protection

| macro                | description                                   |
| -------------------- | --------------------------------------------- |
| `MOON_START_PROTECT` | executes protected code from a hidden section |
| `MOON_END_PROTECT`   | required terminator for protected blocks      |

> must always be paired

---

### string encryption macros

| macro       | return           | description                   |
| ----------- | ---------------- | ----------------------------- |
| `_cat(str)` | encrypted object | compile-time encrypted string |
| `_C(str)`   | `char*`          | decrypted C-string            |
| `_(str)`    | `std::string`    | runtime decrypted string      |
| `_A(str)`   | `LPCSTR`         | WinAPI ANSI string            |
| `_W(str)`   | `std::wstring`   | WinAPI wide string            |

Example:

```cpp
auto s = _cat("example");
s.decrypt();
s.clear();
```

---

### rolling XOR logic

Instead of static XOR:

```
byte ^ key
```

moonprot uses:

* rolling key state
* index-based mutation
* per-byte mixing
* reversible encryption

Each byte:

1. derives a mixed key
2. XORs the byte
3. mutates internal state
4. propagates entropy forward

This prevents:

* repeating patterns
* signature-based recovery
* trivial XOR bruteforce

---

### runtime behavior

* encrypted data only exists in encrypted form in the binary
* decrypted buffer exists only after `decrypt()`
* buffer is mutable
* `clear()` wipes memory manually

No plaintext exists in:

* `.rdata`
* `.text`
* static initializers

---

## callstack & API spoofing

moonprot provides a full **callstack spoofing and shellcode execution system**.

---

## callstack module overview

Namespace: `moonprot::callstack`

Capabilities:

* spoof return addresses
* hide calling functions
* execute APIs through shellcode
* eliminate static callsites

---

## `spoof_function`

```cpp
moonprot::callstack::spoof_func();
```

* Temporarily overwrites the return address of the current stack frame
* XORs return address with `SECURITY_KEY`
* Restores original address automatically via destructor

Example:

```cpp
{
    auto spoof = moonprot::callstack::spoof_func();
    // return address is hidden here
}
```

---

## shellcode execution

### dynamic shellcode allocation

* Uses `VirtualAlloc`
* Allocates `PAGE_EXECUTE_READWRITE`
* Copies function bytes at runtime
* Executes from heap memory

This removes:

* static `.text` callsites
* import-based detection
* predictable call instructions

---

### `shellcode_generator`

* Wraps function execution
* Spoofs return address before call
* Restores after execution
* Supports `void` and non-`void` returns

---

## `safe_call`

```cpp
moonprot::callstack::spoof_call(&SomeApi)(args...);
```

* Encrypts function pointer
* Resolves call at runtime
* Executes via shellcode
* Spoofs callstack during execution
* Caches shellcode for reuse

---

## example: spoofed funtion call

```cpp
moonprot::callstack::spoof_call(&MessageBoxA)(
    nullptr,
    "hello",
    "moonprot",
    MB_OK
);
```

No direct calls exist in `.text`.

---

## protection init

```cpp
moonprot::prot::init();
```

- more details oming soon

---

## notes

* x64 only
* MSVC required
* no CRT / runtime dependencies
* shellcode memory is RWX
* excessive spoofing may impact performance
* designed for advanced Windows-native projects


