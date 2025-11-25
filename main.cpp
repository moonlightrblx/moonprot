#include <iostream>
#include "moonprot/moon.h"

int main()
{
    moonprot::init();

    // xor
    auto secret = moon_xor("login_token_123");
    printf("decrypted should be: login_token_123\n decrypted: %s\n", secret.decrypt());
 

    // encrypted call
    moonprot::enc_call(&MessageBoxA, (HWND)nullptr, "hi", "moonprot", MB_OK);


    system("pause");
}
