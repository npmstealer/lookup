#include <windows.h>
#include <string>
#include <stdio.h>

struct Funcao {
    const char* nome;
    bool hook;
    std::string tipo;
};

Funcao funcoes[] = {
    {"NtCreateFile", false, ""},
    {"NtOpenFile", false, ""},
    {"NtReadFile", false, ""},
    {"NtWriteFile", false, ""},
    {"NtQueryInformationFile", false, ""},
    {"NtSetInformationFile", false, ""},
    {"NtCreateProcess", false, ""},
    {"NtCreateProcessEx", false, ""},
    {"NtOpenProcess", false, ""},
    {"NtTerminateProcess", false, ""}
};

constexpr size_t NUM_FUNCOES = sizeof(funcoes) / sizeof(funcoes[0]);

bool inlinejmp(const char* nome) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    auto addr = (BYTE*)GetProcAddress(ntdll, nome);
    if (!addr) return false;
    return addr[0] == 0xE9;
}

int wmain() {
    int total = 0;
    for (size_t i = 0; i < NUM_FUNCOES; ++i) {
        if (inlinejmp(funcoes[i].nome)) {
            funcoes[i].hook = true;
            funcoes[i].tipo = "MinHook Inline JMP (E9)";
            wprintf(L"[!] %S: %S\n", funcoes[i].nome, funcoes[i].tipo.c_str());
            total++;
        } else {
            wprintf(L"[+] %S\n", funcoes[i].nome);
        }
    }
    if (total == 0) {
        wprintf(L"sem hook");
    } else {
        wprintf(L"[>]: %d\n", total);
        wprintf(L"Funções afetadas > \n");
        for (size_t i = 0; i < NUM_FUNCOES; ++i) {
            if (funcoes[i].hook) {
                wprintf(L"  - %S (%S)\n", funcoes[i].nome, funcoes[i].tipo.c_str());
            }
        }
    }
    return 0;
}
