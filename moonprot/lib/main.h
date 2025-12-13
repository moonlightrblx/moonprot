#pragma once
#include <windows.h>
#include "../helpers.h"
#include "debug.h"
namespace moonprot {
    class prot {
    private:
        prot_func void enable_binary_signature_policy() {

            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = {};
            policy.MicrosoftSignedOnly = 1;
            policy.AuditMicrosoftSignedOnly = 1;
            SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy));

        }
        prot_func void strip_privleges() {

            HANDLE hToken;
            TOKEN_PRIVILEGES tp;
            LUID luid;
            if (OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                if (LookupPrivilegeValueW(NULL, (LPCWSTR)SE_DEBUG_NAME, &luid)) {
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
                    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
                }
                CloseHandle(hToken);
            }
        }

        prot_func void thread() {
            while (1) {
                if (IsDebuggerPresent()) {
                    _exit(0);
                }
                Sleep(10000); // every 10 seconds to not give ur cpu aids <3
            }
        }
    public:


        prot_func void init() {
            enable_binary_signature_policy();
            strip_privleges();
            std::thread(moonprot::anti_debug).detach();
            std::thread(thread).detach();
        }
    };
}