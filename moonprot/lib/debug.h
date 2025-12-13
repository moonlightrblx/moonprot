#pragma once
#include "../helpers.h"
#include "xor.h"

#include <Windows.h>
#include <vector>
#include <mutex>
#include <TlHelp32.h>
#include <algorithm>

struct HardwareBreakpoint {
    DWORD64 address;
    DWORD type;
    bool enabled;
};

static std::vector<HardwareBreakpoint> hardware_breakpoints;
static std::mutex breakpoints_mutex;

static inline bool is_blacklisted_process(const std::string& processName) {
    const std::vector<std::string> blacklist = {
        _("ollydbg.exe"), _("x64dbg.exe"), _("x32dbg.exe"), _("ida.exe"), _("ida64.exe"),
        _("ghidra.exe"), _("dnspy.exe"), _("cheatengine"), _("processhacker.exe"),
        _("httpdebugger.exe"), _("procmon.exe"), _("processhacker.exe"), _("pestudio.exe"),
        _("regmon.exe"), _("filemon.exe"), _("wireshark.exe"), _("fiddler.exe"),
        _("procexp.exe"), _("procmon.exe"), _("immunitydebugger.exe"), _("windbg.exe"),
        _("debugger.exe"), _("dumpcap.exe"), _("hookexplorer.exe"), _("importrec.exe"),
        _("petools.exe"), _("lordpe.exe"), _("sysinspector.exe"), _("proc_analyzer.exe"),
        _("sysanalyzer.exe"), _("sniff_hit.exe"), _("windbg.exe"), _("apimonitor.exe"),
        _("dumpcap.exe"), _("networktrafficview.exe"), _("charles.exe"), _("scylla.exe")
    };

    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    return std::find_if(blacklist.begin(), blacklist.end(),
        [&lowerName](const std::string& blocked) {
            return lowerName.find(blocked) != std::string::npos;
        }) != blacklist.end();
}

static inline bool check_hardware_breakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE thread = GetCurrentThread();
    if (!GetThreadContext(thread, &ctx)) return false;

    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        return true;
    }

    return false;
}
static inline bool check_running_analysis_tools() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    bool found = false;

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            char processName[MAX_PATH];
            wcstombs_s(nullptr, processName, pe32.szExeFile, MAX_PATH);

            if (is_blacklisted_process(processName)) {
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return found;
}
static inline bool check_parent_process() {
    DWORD pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                DWORD parentPID = pe32.th32ParentProcessID;
                Process32FirstW(snapshot, &pe32);

                do {
                    if (pe32.th32ProcessID == parentPID) {
                        char processName[MAX_PATH];
                        wcstombs_s(nullptr, processName, pe32.szExeFile, MAX_PATH);

                        if (is_blacklisted_process(processName)) {
                            CloseHandle(snapshot);
                            return true;
                        }
                        break;
                    }
                } while (Process32NextW(snapshot, &pe32));
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return false;
}

namespace moonprot {
    prot_func void anti_debug() {
        while (true) {
            if (check_hardware_breakpoints()) {
                DWORD oldProtect;
                HANDLE process = GetCurrentProcess();
                for (const auto& bp : hardware_breakpoints) {
                    if (VirtualProtect((LPVOID)bp.address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        *(BYTE*)bp.address = 0x90;
                        VirtualProtect((LPVOID)bp.address, 1, oldProtect, &oldProtect);
                    }
                }
            }
            check_parent_process();
            check_running_analysis_tools();
            Sleep(110);

        }
    }
}