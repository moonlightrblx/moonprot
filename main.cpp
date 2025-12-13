#include <iostream>
#include "moonprot/includes.h"

int main()
{
    MOON_START_PROTECT // this just creates a `.hidden` code section that is seperate from the normal .text section 
    moonprot::callstack::spoof_func(); // spoofs the main function callstack address

    moonprot::prot::init(); // note: you can technically spoof_call all functions but sometimes its not needed / worth the performance drop.

    // xor
    auto secret = _cat("login_token_123");
    printf("decrypted should be: login_token_123\ndecrypted: %s\n", secret.decrypt());
    secret.clear(); // should null the secret in memory so x64dbg or other strings detectors cannot read

    printf("calling encrypted MessageBoxA\n");
    // encrypted call to messageboxa
    moonprot::callstack::spoof_call(&MessageBoxA)(
        (HWND)nullptr,
        "hi",
        "moonprot",
        MB_OK
        );

    MOON_END_PROTECT // make sure to add this otherwise you might have huge issues.

    system("pause > nul");
}
