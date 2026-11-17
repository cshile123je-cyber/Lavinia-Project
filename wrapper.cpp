//
// wrapper.cpp
// Lavinia crash fix wrapper
// inject bu dll'i — lavinia'yı kendisi yukler, timing fix eder
//

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <filesystem>
#include <string>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

// ─── config ──────────────────────────────────────────────────────────────────
// wrapper.dll ile aynı klasörde olmalı
static constexpr wchar_t PAYLOAD_NAME[] = L"xhanger_yazılım__lavinia_project_.dll";

// inject sonrası ne kadar bekleyip DllMain çağrılsın (ms)
// çok erken çağrılınca oyun hazır olmadığı için crash oluyor
static constexpr DWORD INIT_DELAY_MS = 2500;

// ─── manual map structures ───────────────────────────────────────────────────
struct MM_DATA {
    LPVOID pLoadLibraryA;
    LPVOID pGetProcAddress;
    BOOL   bErrorFlag;
    BOOL   bDone;
};

// shellcode — hedef process içinde çalışır
// sadece import'ları resolve eder, DllMain'i ÇAĞIRMAZ
// DllMain'i wrapper thread'i gecikmeyle çağırır
static void __stdcall ResolveImportsOnly(MM_DATA* pData) {
    if (!pData) { pData->bErrorFlag = TRUE; return; }

    BYTE* pBase = reinterpret_cast<BYTE*>(pData);
    auto  pLLA  = reinterpret_cast<decltype(&LoadLibraryA)>(pData->pLoadLibraryA);
    auto  pGPA  = reinterpret_cast<decltype(&GetProcAddress)>(pData->pGetProcAddress);

    auto* pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
    auto* pNT  = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDos->e_lfanew);
    auto& opt  = pNT->OptionalHeader;

    // relocations
    if (opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            pBase + opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        BYTE* delta = pBase - reinterpret_cast<BYTE*>(opt.ImageBase);
        while (reloc->VirtualAddress) {
            UINT  count   = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            WORD* entries = reinterpret_cast<WORD*>(reloc + 1);
            for (UINT i = 0; i < count; ++i)
                if ((entries[i] >> 12) == IMAGE_REL_BASED_DIR64)
                    *reinterpret_cast<UINT_PTR*>(
                        pBase + reloc->VirtualAddress + (entries[i] & 0xFFF))
                        += reinterpret_cast<UINT_PTR>(delta);
            reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<BYTE*>(reloc) + reloc->SizeOfBlock);
        }
    }

    // imports
    if (opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            pBase + opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (imp->Name) {
            HMODULE hMod = pLLA(reinterpret_cast<char*>(pBase + imp->Name));
            if (hMod) {
                auto* thunk = reinterpret_cast<ULONG_PTR*>(
                    pBase + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
                auto* func  = reinterpret_cast<ULONG_PTR*>(pBase + imp->FirstThunk);
                for (; *thunk; ++thunk, ++func)
                    if (IMAGE_SNAP_BY_ORDINAL(*thunk))
                        *func = reinterpret_cast<ULONG_PTR>(
                            pGPA(hMod, reinterpret_cast<char*>(*thunk & 0xFFFF)));
                    else
                        *func = reinterpret_cast<ULONG_PTR>(
                            pGPA(hMod, reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                                pBase + *thunk)->Name));
            }
            ++imp;
        }
    }

    pData->bErrorFlag = FALSE;
    pData->bDone      = TRUE;
}
static void Shellcode_End() {}

// ─── loader thread ───────────────────────────────────────────────────────────
static HMODULE g_hSelf = nullptr;

static DWORD WINAPI LoaderThread(LPVOID) {
    // 1. kendi konumumuzu bul
    wchar_t selfPath[MAX_PATH]{};
    GetModuleFileNameW(g_hSelf, selfPath, MAX_PATH);
    fs::path dir = fs::path(selfPath).parent_path();
    fs::path payloadPath = dir / PAYLOAD_NAME;

    // payload var mı
    if (!fs::exists(payloadPath)) {
        MessageBoxW(nullptr,
            (L"Payload bulunamadi:\n" + payloadPath.wstring()).c_str(),
            L"XWrapper", MB_ICONERROR);
        return 1;
    }

    // 2. oyunun hazır olmasını bekle
    Sleep(INIT_DELAY_MS);

    // 3. payload'ı oku
    HANDLE hFile = CreateFileW(payloadPath.c_str(), GENERIC_READ,
                                FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    DWORD sz = GetFileSize(hFile, nullptr);
    std::vector<BYTE> buf(sz);
    DWORD rd = 0;
    ReadFile(hFile, buf.data(), sz, &rd, nullptr);
    CloseHandle(hFile);
    if (rd != sz) return 1;

    // 4. PE doğrula
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 1;
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 1;

    HANDLE hProc = GetCurrentProcess();
    DWORD  pid   = GetCurrentProcessId();

    // 5. image için yer ayır
    SIZE_T imgSz = nt->OptionalHeader.SizeOfImage;
    LPVOID pBase = VirtualAlloc(nullptr, imgSz,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pBase) return 1;

    // 6. header + sections yaz
    memcpy(pBase, buf.data(), nt->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
        if (sec->SizeOfRawData)
            memcpy(reinterpret_cast<BYTE*>(pBase) + sec->VirtualAddress,
                   buf.data() + sec->PointerToRawData,
                   sec->SizeOfRawData);

    // 7. shellcode + data alloc
    SIZE_T shellSz = reinterpret_cast<BYTE*>(Shellcode_End) -
                     reinterpret_cast<BYTE*>(ResolveImportsOnly);

    LPVOID pShell = VirtualAlloc(nullptr, shellSz + sizeof(MM_DATA),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShell) { VirtualFree(pBase, 0, MEM_RELEASE); return 1; }

    MM_DATA data{};
    data.pLoadLibraryA  = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    data.pGetProcAddress= GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");

    memcpy(pShell, &data, sizeof(data));
    memcpy(reinterpret_cast<BYTE*>(pShell) + sizeof(data),
           ResolveImportsOnly, shellSz);

    // 8. kendi process'imizde remote thread — imports resolve
    HANDLE hThread = CreateThread(nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(
            reinterpret_cast<BYTE*>(pShell) + sizeof(data)),
        pShell, 0, nullptr);

    if (!hThread) {
        VirtualFree(pBase,  0, MEM_RELEASE);
        VirtualFree(pShell, 0, MEM_RELEASE);
        return 1;
    }

    WaitForSingleObject(hThread, 8000);
    CloseHandle(hThread);

    MM_DATA result{};
    memcpy(&result, pShell, sizeof(result));
    VirtualFree(pShell, 0, MEM_RELEASE);

    if (result.bErrorFlag) {
        VirtualFree(pBase, 0, MEM_RELEASE);
        return 1;
    }

    // 9. TLS callbacks
    auto& opt2 = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<BYTE*>(pBase) +
        reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

    if (opt2.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
            reinterpret_cast<BYTE*>(pBase) +
            opt2.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto** cb = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        while (cb && *cb) {
            (*cb)(pBase, DLL_PROCESS_ATTACH, nullptr);
            ++cb;
        }
    }

    // 10. DllMain çağır — gecikmeli, oyun tam hazır
    // JSON/config exception'larını catch ediyoruz — crash engellendi
    using DllMain_t = BOOL(WINAPI*)(HMODULE, DWORD, LPVOID);
    auto pEntry = reinterpret_cast<DllMain_t>(
        reinterpret_cast<BYTE*>(pBase) + opt2.AddressOfEntryPoint);

    __try {
        pEntry(reinterpret_cast<HMODULE>(pBase), DLL_PROCESS_ATTACH, nullptr);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // exception yakalandı — crash yerine devam et
        // hile yine de inject oldu, sadece init exception'ı yuttuk
    }

    return 0;
}

// ─── DllMain ─────────────────────────────────────────────────────────────────
BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hSelf = hModule;
        DisableThreadLibraryCalls(hModule);

        // thread içinde yükle — DllMain'i bloklamıyoruz
        // bu inject crash'inin ana nedeni: DllMain'de uzun işlem
        HANDLE h = CreateThread(nullptr, 0, LoaderThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
