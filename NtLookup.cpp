#include <windows.h>
#include <string>
#include <psapi.h>
#include <vector>
#include <tlhelp32.h>
#include <map>
#include <shellapi.h>
#include <winnt.h>
#include <set>

struct Funcao {
    const char* nome;
    bool hook;
    std::string tipo;
};

Funcao funcoes[] = {
    {"NtCreateFile", false, ""}, {"NtOpenFile", false, ""}, {"NtReadFile", false, ""},
    {"NtWriteFile", false, ""}, {"NtQueryInformationFile", false, ""}, {"NtSetInformationFile", false, ""},
    {"NtCreateProcess", false, ""}, {"NtCreateProcessEx", false, ""}, {"NtOpenProcess", false, ""},
    {"NtTerminateProcess", false, ""}
};

constexpr size_t NUM_FUNCOES = sizeof(funcoes) / sizeof(funcoes[0]);

bool detecta_trampoline(const BYTE* code, SIZE_T size, std::string& tipo) {
    if (size < 6) return false;

    if (code[0] == 0xE9) {
        tipo = "[jmp rel32]";
        return true;
    }
    if (code[0] == 0xEB) {
        tipo = "[jmp rel8]";
        return true;
    }
    if (code[0] == 0xE8) {
        tipo = "[call rel32]";
        return true;
    }
    if ((code[0] == 0x68 && code[5] == 0xC3) || (code[0] == 0x68 && code[5] == 0xCB)) {
        tipo = "[push+ret]";
        return true;
    }
    if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0) {
        tipo = "[mov rax+jmp rax]";
        return true;
    }
    if (code[0] == 0xB8 && code[5] == 0xFF && code[6] == 0xE0) {
        tipo = "[mov eax+jmp eax]";
        return true;
    }
    if (code[0] == 0xFF && (code[1] & 0xF8) == 0x20) {
        tipo = "[jmp indireto]";
        return true;
    }

    return false;
}

bool udEat(HANDLE hProcess, HMODULE hModule, const char* nomeFunc, FARPROC localProc, std::string& tipo) {
    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER dos = {0};
    if (!ReadProcessMemory(hProcess, base, &dos, sizeof(dos), nullptr) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS64 nth = {0};
    if (!ReadProcessMemory(hProcess, base + dos.e_lfanew, &nth, sizeof(nth), nullptr) || nth.Signature != IMAGE_NT_SIGNATURE)
        return false;

    DWORD exportRVA = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRVA) return false;

    IMAGE_EXPORT_DIRECTORY exp = {0};
    if (!ReadProcessMemory(hProcess, base + exportRVA, &exp, sizeof(exp), nullptr))
        return false;

    std::vector<DWORD> funcRVAs(exp.NumberOfFunctions);
    if (!ReadProcessMemory(hProcess, base + exp.AddressOfFunctions, funcRVAs.data(), exp.NumberOfFunctions * sizeof(DWORD), nullptr))
        return false;

    std::vector<DWORD> nameRVAs(exp.NumberOfNames);
    if (!ReadProcessMemory(hProcess, base + exp.AddressOfNames, nameRVAs.data(), exp.NumberOfNames * sizeof(DWORD), nullptr))
        return false;

    std::vector<WORD> ordinals(exp.NumberOfNames);
    if (!ReadProcessMemory(hProcess, base + exp.AddressOfNameOrdinals, ordinals.data(), exp.NumberOfNames * sizeof(WORD), nullptr))
        return false;

    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        char nome[128] = {0};
        ReadProcessMemory(hProcess, base + nameRVAs[i], nome, sizeof(nome) - 1, nullptr);
        if (strcmp(nome, nomeFunc) == 0) {
            DWORD funcRVA = funcRVAs[ordinals[i]];
            FARPROC remoteProc = (FARPROC)(base + funcRVA);
            if ((uintptr_t)remoteProc != (uintptr_t)localProc) {
                tipo = "[EAT hook]";
                return true;
            }
        }
    }
    return false;
}

bool udIat(HANDLE hProcess, HMODULE hModule, const char* nomeFunc, FARPROC localProc, std::string& tipo) {
    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER dos = {0};
    if (!ReadProcessMemory(hProcess, base, &dos, sizeof(dos), nullptr) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS64 nth = {0};
    if (!ReadProcessMemory(hProcess, base + dos.e_lfanew, &nth, sizeof(nth), nullptr) || nth.Signature != IMAGE_NT_SIGNATURE)
        return false;

    DWORD importRVA = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRVA) return false;

    IMAGE_IMPORT_DESCRIPTOR imp = {0};
    SIZE_T offset = 0;
    while (true) {
        if (!ReadProcessMemory(hProcess, base + importRVA + offset, &imp, sizeof(imp), nullptr) || imp.Name == 0)
            break;

        char dllName[128] = {0};
        ReadProcessMemory(hProcess, base + imp.Name, dllName, sizeof(dllName) - 1, nullptr);

        SIZE_T thunkOffset = 0;
        IMAGE_THUNK_DATA64 thunk = {0};
        while (true) {
            if (!ReadProcessMemory(hProcess, base + imp.FirstThunk + thunkOffset, &thunk, sizeof(thunk), nullptr) || thunk.u1.Function == 0)
                break;

            FARPROC remoteProc = (FARPROC)thunk.u1.Function;
            if (remoteProc && (uintptr_t)remoteProc != (uintptr_t)localProc) {
                tipo = "[IAT hook]";
                return true;
            }
            thunkOffset += sizeof(IMAGE_THUNK_DATA64);
        }
        offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return false;
}

bool inlinehook(HANDLE hProcess, const char* nome) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
    FARPROC localProc = GetProcAddress(hNtdll, nome);
    if (!localProc) return false;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return false;

    HMODULE remoteNtdll = nullptr;
    WCHAR ntdllName[MAX_PATH];
    for (unsigned i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
        if (GetModuleBaseNameW(hProcess, hMods[i], ntdllName, MAX_PATH)) {
            if (_wcsicmp(ntdllName, L"ntdll.dll") == 0) {
                remoteNtdll = hMods[i];
                break;
            }
        }
    }
    if (!remoteNtdll) return false;

    uintptr_t offset = (BYTE*)localProc - (BYTE*)hNtdll;
    BYTE remoteBytes[16] = {0};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (BYTE*)remoteNtdll + offset, remoteBytes, sizeof(remoteBytes), &bytesRead) || bytesRead < 6)
        return false;

    std::string tipo;
    if (detecta_trampoline(remoteBytes, bytesRead, tipo)) {
        return true;
    }
    return false;
}

bool eat_iat_hook(HANDLE hProcess, HMODULE hModule, const char* nome, FARPROC localProc, std::string& tipo) {
    if (udEat(hProcess, hModule, nome, localProc, tipo))
        return true;
    if (udIat(hProcess, hModule, nome, localProc, tipo))
        return true;
    return false;
}

bool modulado(HANDLE hProcess, LPVOID addr) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
            MODULEINFO mi;
            if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                BYTE* base = (BYTE*)mi.lpBaseOfDll;
                if ((BYTE*)addr >= base && (BYTE*)addr < base + mi.SizeOfImage) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool listado(const std::vector<LPVOID>& lista, LPVOID addr) {
    for (auto e : lista) {
        if (e == addr)
            return true;
    }
    return false;
}

bool enderecop(LPVOID addr) {
    uintptr_t a = (uintptr_t)addr;
    if (a == 0) return false;
#ifdef _WIN64
    if (a < 0x10000) return false;
    if (a > 0x7FFFFFFFFFFF) return false;
#else
    if (a < 0x10000) return false;
    if (a > 0x7FFFFFFF) return false;
#endif
    return true;
}

bool injetorpriv(HANDLE hProcess, DWORD pid, std::vector<LPVOID>& suspeitos, bool& memoria_rwx) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    std::set<LPVOID> suspeitos_set;
    if (hSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(te);
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, 0, te.th32ThreadID);
                    if (hThread) {
                        typedef NTSTATUS(WINAPI* pNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
                        auto NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
                        if (NtQueryInformationThread) {
                            LPVOID startAddr = nullptr;
                            if (NtQueryInformationThread(hThread, 9, &startAddr, sizeof(startAddr), NULL) == 0 && startAddr) {
                                if (enderecop(startAddr) && !modulado(hProcess, startAddr)) {
                                    if (suspeitos_set.find(startAddr) == suspeitos_set.end()) {
                                        suspeitos.push_back(startAddr);
                                        suspeitos_set.insert(startAddr);
                                    }
                                }
                            }
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }
    memoria_rwx = false;
    return (!suspeitos.empty());
}

bool ademenistrador() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isAdmin) {
        WCHAR szPath[MAX_PATH];
        if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
            SHELLEXECUTEINFOW sei = { sizeof(sei) };
            sei.lpVerb = L"runas";
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_SHOWNORMAL;
            if (!ShellExecuteExW(&sei)) {
                return false;
            }
            return false;
        }
    }
    return true;
}

void superprivadoprocesso() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    std::map<DWORD, std::wstring> pid_nome;
    std::vector<DWORD> pids;
    if (Process32First(hSnap, &pe)) {
        do {
            pid_nome[pe.th32ProcessID] = pe.szExeFile;
            pids.push_back(pe.th32ProcessID);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    for (DWORD pid : pids) {
        if (pid == 0 || pid == 4) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) continue;

        int total_hooks = 0;
        std::vector<Funcao> funcoes_proc(NUM_FUNCOES);
        memcpy(funcoes_proc.data(), funcoes, sizeof(funcoes));
        HMODULE hNtdllRemote = NULL;
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                WCHAR ntdllName[MAX_PATH];
                if (GetModuleBaseNameW(hProcess, hMods[i], ntdllName, MAX_PATH)) {
                    if (_wcsicmp(ntdllName, L"ntdll.dll") == 0) {
                        hNtdllRemote = hMods[i];
                        break;
                    }
                }
            }
        }

        for (size_t i = 0; i < NUM_FUNCOES; ++i) {
            std::string tipo;
            bool hook_detectado = false;
            if (inlinehook(hProcess, funcoes_proc[i].nome)) {
                tipo = "[trampoline]";
                hook_detectado = true;
            }
            HMODULE hNtdllLocal = GetModuleHandleW(L"ntdll.dll");
            FARPROC localProc = GetProcAddress(hNtdllLocal, funcoes_proc[i].nome);
            if (hNtdllRemote && eat_iat_hook(hProcess, hNtdllRemote, funcoes_proc[i].nome, localProc, tipo)) {
                hook_detectado = true;
            }
            if (hook_detectado) {
                funcoes_proc[i].hook = true;
                funcoes_proc[i].tipo = tipo;
                total_hooks++;
            }
        }

        std::vector<LPVOID> suspeitos;
        bool memoria_rwx = false;
        bool inject_detectado = injetorpriv(hProcess, pid, suspeitos, memoria_rwx);

        std::set<LPVOID> suspeitos_unicos(suspeitos.begin(), suspeitos.end());
        bool mostrar_threads = !suspeitos_unicos.empty() && (suspeitos_unicos.size() <= 5);

        if (total_hooks > 0 || mostrar_threads) {
            wprintf(L"\n[!] Processo: %s [PID: %lu]\n", pid_nome[pid].c_str(), pid);
            if (total_hooks > 0) {
                wprintf(L"    [>] função hookada\n");
                for (size_t i = 0; i < NUM_FUNCOES; ++i) {
                    if (funcoes_proc[i].hook)
                        wprintf(L"      - %S (%S)\n", funcoes_proc[i].nome, funcoes_proc[i].tipo.c_str());
                }
            }
            if (mostrar_threads) {
                wprintf(L"    [+] thread estranha\n");
                for (auto e : suspeitos_unicos)
                    wprintf(L"      - 0x%p\n", e);
            }
        }
        CloseHandle(hProcess);
    }
}

int wmain() {
    if (!ademenistrador()) {
        return 1;
    }
    superprivadoprocesso();
    return 0;
}
