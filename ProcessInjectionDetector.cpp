// ============================================================
// ProcessInjectionDetector.cpp
// Process Injection Tespit Aracı - Ana Uygulama Dosyası
// ============================================================

#include "ProcessInjectionDetector.h"
#include <algorithm>
#include <cctype>

ProcessInjectionDetector::ProcessInjectionDetector() : m_verbose(true) {
    m_suspiciousPaths = {
        L"\\Temp\\",
        L"\\AppData\\Local\\Temp\\",
        L"\\Users\\Public\\",
        L"\\ProgramData\\",
        L"\\Downloads\\"
    };
    m_knownGoodPaths = {
        L"C:\\Windows\\System32\\",
        L"C:\\Windows\\SysWOW64\\",
        L"C:\\Windows\\WinSxS\\",
        L"C:\\Program Files\\",
        L"C:\\Program Files (x86)\\"
    };
}

ProcessInjectionDetector::~ProcessInjectionDetector() {}

// ============================================================
// Tüm Süreçleri Tara
// ============================================================
void ProcessInjectionDetector::ScanAllProcesses() {
    std::wcout << L"\n[*] Tüm süreçler taranıyor...\n";
    std::wcout << L"[*] Zaman: " << GetCurrentTimestamp() << L"\n";
    std::wcout << L"====================================================\n";

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[HATA] Süreç listesi alınamadı!\n";
        return;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return;
    }

    do {
        if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4) continue;
        if (IsSystemProcess(pe32.szExeFile)) continue;
        ScanProcess(pe32.th32ProcessID);
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    std::wcout << L"\n[+] Tarama tamamlandı. Toplam tespit: " << m_results.size() << L"\n";
}

// ============================================================
// Tek Bir Süreci Tara
// ============================================================
void ProcessInjectionDetector::ScanProcess(DWORD pid) {
    std::wstring procName = GetProcessName(pid);

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    if (m_verbose)
        std::wcout << L"\n[>] Süreç taranıyor: [" << pid << L"] " << procName << L"\n";

    DetectDLLInjection(pid, procName);
    DetectProcessHollowing(pid, procName);
    DetectShellcodeInjection(pid, procName);
    DetectRemoteThreads(pid, procName);
    DetectAPCInjection(pid, procName);

    CloseHandle(hProcess);
}

// ============================================================
// 1. DLL Injection Tespiti
// ============================================================
void ProcessInjectionDetector::DetectDLLInjection(DWORD pid, const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (!Module32FirstW(hSnapshot, &me32)) {
        CloseHandle(hSnapshot);
        return;
    }

    do {
        std::wstring modPath = me32.szExePath;
        if (IsPathSuspicious(modPath)) {
            DetectionResult result;
            result.injectionDetected = true;
            result.processName = processName;
            result.processId = pid;
            result.injectionType = L"DLL Injection";
            result.description = L"Şüpheli konumdan DLL yüklendi: " + modPath;
            result.severity = L"HIGH";
            result.timestamp = GetCurrentTimestamp();
            m_results.push_back(result);

            std::wcout << L"  [!!!] DLL INJECTION TESPİT EDİLDİ!\n";
            std::wcout << L"        Modül: " << me32.szModule << L"\n";
            std::wcout << L"        Yol  : " << modPath << L"\n";
        }
    } while (Module32NextW(hSnapshot, &me32));

    CloseHandle(hSnapshot);
}

// ============================================================
// 2. Process Hollowing Tespiti
// ============================================================
void ProcessInjectionDetector::DetectProcessHollowing(DWORD pid, const std::wstring& processName) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    wchar_t exePath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameExW(hProcess, NULL, exePath, MAX_PATH)) {
        CloseHandle(hProcess);
        return;
    }

    HANDLE hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return;
    }

    BYTE diskHeader[0x1000] = { 0 };
    DWORD bytesRead = 0;
    ReadFile(hFile, diskHeader, sizeof(diskHeader), &bytesRead, NULL);
    CloseHandle(hFile);

    BYTE memHeader[0x1000] = { 0 };
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        SIZE_T bytesReadMem = 0;
        ReadProcessMemory(hProcess, hMods[0], memHeader, sizeof(memHeader), &bytesReadMem);
    }

    if (memHeader[0] != 'M' || memHeader[1] != 'Z') {
        DetectionResult result;
        result.injectionDetected = true;
        result.processName = processName;
        result.processId = pid;
        result.injectionType = L"Process Hollowing";
        result.description = L"Bellekte geçersiz PE başlığı (MZ imzası yok)";
        result.severity = L"HIGH";
        result.timestamp = GetCurrentTimestamp();
        m_results.push_back(result);

        std::wcout << L"  [!!!] PROCESS HOLLOWING TESPİT EDİLDİ! (" << processName << L")\n";
    }
    else {
        PIMAGE_DOS_HEADER diskDos = (PIMAGE_DOS_HEADER)diskHeader;
        PIMAGE_DOS_HEADER memDos = (PIMAGE_DOS_HEADER)memHeader;
        if (diskDos->e_lfanew != memDos->e_lfanew) {
            DetectionResult result;
            result.injectionDetected = true;
            result.processName = processName;
            result.processId = pid;
            result.injectionType = L"Process Hollowing";
            result.description = L"PE başlığı disk-bellek uyuşmazlığı";
            result.severity = L"HIGH";
            result.timestamp = GetCurrentTimestamp();
            m_results.push_back(result);

            std::wcout << L"  [!!!] PROCESS HOLLOWING ŞÜPHESİ! (" << processName << L")\n";
        }
    }

    CloseHandle(hProcess);
}

// ============================================================
// 3. Shellcode Injection Tespiti
// ============================================================
void ProcessInjectionDetector::DetectShellcodeInjection(DWORD pid, const std::wstring& processName) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    MEMORY_BASIC_INFORMATION mbi;
    PBYTE addr = 0;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        bool isRWX = (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
            (mbi.Protect & PAGE_EXECUTE_WRITECOPY);

        if (isRWX && mbi.State == MEM_COMMIT && mbi.RegionSize > 0) {
            DetectionResult result;
            result.injectionDetected = true;
            result.processName = processName;
            result.processId = pid;
            result.injectionType = L"Shellcode Injection";
            result.description = L"RWX bellek bölgesi tespit edildi";
            result.severity = L"HIGH";
            result.timestamp = GetCurrentTimestamp();
            m_results.push_back(result);

            std::wcout << L"  [!!!] RWX BELLEK TESPİT EDİLDİ! (" << processName << L")\n";
            std::wcout << L"        Adres: 0x" << std::hex
                << (uintptr_t)mbi.BaseAddress << std::dec
                << L" | Boyut: " << mbi.RegionSize << L" bayt\n";
        }

        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        if ((uintptr_t)addr > 0x7FFFFFFF) break;
    }

    CloseHandle(hProcess);
}

// ============================================================
// 4. Remote Thread Tespiti
// ============================================================
void ProcessInjectionDetector::DetectRemoteThreads(DWORD pid, const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hSnapshot, &te32)) {
        CloseHandle(hSnapshot);
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    do {
        if (te32.th32OwnerProcessID != pid) continue;

        HANDLE hThread = OpenThread(
            THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, te32.th32ThreadID);
        if (!hThread) continue;

        PVOID startAddr = GetThreadStartAddress(hThread);
        if (startAddr && hProcess) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, startAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.Type == MEM_PRIVATE &&
                    (mbi.Protect & PAGE_EXECUTE_READ ||
                        mbi.Protect & PAGE_EXECUTE_READWRITE)) {

                    DetectionResult result;
                    result.injectionDetected = true;
                    result.processName = processName;
                    result.processId = pid;
                    result.injectionType = L"Remote Thread Injection";
                    result.description = L"Thread private execute alanında başlıyor. TID: "
                        + std::to_wstring(te32.th32ThreadID);
                    result.severity = L"MEDIUM";
                    result.timestamp = GetCurrentTimestamp();
                    m_results.push_back(result);

                    std::wcout << L"  [!!] REMOTE THREAD ŞÜPHESİ! (" << processName << L")\n";
                    std::wcout << L"       Thread ID: " << te32.th32ThreadID << L"\n";
                }
            }
        }
        CloseHandle(hThread);
    } while (Thread32Next(hSnapshot, &te32));

    if (hProcess) CloseHandle(hProcess);
    CloseHandle(hSnapshot);
}

// ============================================================
// 5. APC Injection Tespiti
// ============================================================
void ProcessInjectionDetector::DetectAPCInjection(DWORD pid, const std::wstring& processName) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    int suspiciousModCount = 0;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        int modCount = cbNeeded / sizeof(HMODULE);
        for (int i = 1; i < modCount; i++) {
            wchar_t modPath[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(hProcess, hMods[i], modPath, MAX_PATH)) {
                if (IsPathSuspicious(modPath)) suspiciousModCount++;
            }
        }
    }

    if (suspiciousModCount >= 2) {
        DetectionResult result;
        result.injectionDetected = true;
        result.processName = processName;
        result.processId = pid;
        result.injectionType = L"APC Injection (Heuristic)";
        result.description = L"Çoklu şüpheli modül yüklemesi: "
            + std::to_wstring(suspiciousModCount) + L" adet";
        result.severity = L"MEDIUM";
        result.timestamp = GetCurrentTimestamp();
        m_results.push_back(result);

        std::wcout << L"  [!!] APC INJECTION ŞÜPHESİ! (" << processName << L")\n";
    }

    CloseHandle(hProcess);
}

// ============================================================
// Yardımcı Metodlar
// ============================================================
std::wstring ProcessInjectionDetector::GetProcessName(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return L"Unknown";

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                return pe32.szExeFile;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return L"Unknown";
}

std::wstring ProcessInjectionDetector::GetCurrentTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return buf;
}

bool ProcessInjectionDetector::IsSystemProcess(const std::wstring& name) {
    static const std::vector<std::wstring> sys = {
        L"System", L"smss.exe", L"csrss.exe", L"wininit.exe",
        L"winlogon.exe", L"services.exe", L"lsass.exe",
        L"svchost.exe", L"dwm.exe"
    };
    for (const auto& s : sys)
        if (_wcsicmp(name.c_str(), s.c_str()) == 0) return true;
    return false;
}

bool ProcessInjectionDetector::IsPathSuspicious(const std::wstring& path) {
    std::wstring lpath = path;
    std::transform(lpath.begin(), lpath.end(), lpath.begin(), ::towlower);
    for (const auto& sus : m_suspiciousPaths) {
        std::wstring sl = sus;
        std::transform(sl.begin(), sl.end(), sl.begin(), ::towlower);
        if (lpath.find(sl) != std::wstring::npos) return true;
    }
    return false;
}

bool ProcessInjectionDetector::IsModuleSignedOrKnown(const std::wstring& path) {
    std::wstring lpath = path;
    std::transform(lpath.begin(), lpath.end(), lpath.begin(), ::towlower);
    for (const auto& good : m_knownGoodPaths) {
        std::wstring gl = good;
        std::transform(gl.begin(), gl.end(), gl.begin(), ::towlower);
        if (lpath.find(gl) != std::wstring::npos) return true;
    }
    return false;
}

PVOID ProcessInjectionDetector::GetThreadStartAddress(HANDLE hThread) {
    typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    static NtQueryInformationThread_t fn = nullptr;
    if (!fn) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll)
            fn = (NtQueryInformationThread_t)
            GetProcAddress(ntdll, "NtQueryInformationThread");
    }
    if (!fn) return nullptr;

    PVOID startAddr = nullptr;
    fn(hThread, 9, &startAddr, sizeof(startAddr), nullptr);
    return startAddr;
}

std::wstring ProcessInjectionDetector::ProtectFlagsToString(DWORD protect) {
    switch (protect) {
    case PAGE_EXECUTE:           return L"PAGE_EXECUTE";
    case PAGE_EXECUTE_READ:      return L"PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return L"PAGE_EXECUTE_READWRITE (RWX!)";
    case PAGE_READONLY:          return L"PAGE_READONLY";
    case PAGE_READWRITE:         return L"PAGE_READWRITE";
    default: return L"UNKNOWN";
    }
}

// ============================================================
// Sonuçları Göster
// ============================================================
void ProcessInjectionDetector::PrintResults() {
    std::wcout << L"\n====================================================\n";
    std::wcout << L"   PROCESS INJECTION TESPİT RAPORU\n";
    std::wcout << L"====================================================\n";

    if (m_results.empty()) {
        std::wcout << L"[+] Herhangi bir injection tespiti yapılmadı.\n";
        return;
    }

    int high = 0, medium = 0;
    for (const auto& r : m_results) {
        if (r.severity == L"HIGH")   high++;
        else if (r.severity == L"MEDIUM") medium++;
    }

    std::wcout << L"Toplam : " << m_results.size() << L"\n";
    std::wcout << L"  HIGH   : " << high << L"\n";
    std::wcout << L"  MEDIUM : " << medium << L"\n";
    std::wcout << L"----------------------------------------------------\n";

    for (size_t i = 0; i < m_results.size(); i++) {
        const auto& r = m_results[i];
        std::wcout << L"\n[" << (i + 1) << L"] " << r.severity
            << L" | " << r.injectionType << L"\n";
        std::wcout << L"    Süreç    : " << r.processName
            << L" (PID: " << r.processId << L")\n";
        std::wcout << L"    Açıklama : " << r.description << L"\n";
        std::wcout << L"    Zaman    : " << r.timestamp << L"\n";
    }
    std::wcout << L"\n====================================================\n";
}

// ============================================================
// Log Kaydet
// ============================================================
void ProcessInjectionDetector::SaveLog(const std::wstring& filename) {
    std::wofstream log(filename);
    if (!log.is_open()) {
        std::wcerr << L"[HATA] Log dosyası açılamadı!\n";
        return;
    }
    log << L"PROCESS INJECTION TESPIT RAPORU\n";
    log << L"Tarih: " << GetCurrentTimestamp() << L"\n\n";
    for (const auto& r : m_results) {
        log << L"[" << r.severity << L"] " << r.injectionType << L"\n";
        log << L"Süreç   : " << r.processName << L" (PID: " << r.processId << L")\n";
        log << L"Açıklama: " << r.description << L"\n";
        log << L"Zaman   : " << r.timestamp << L"\n\n";
    }
    log.close();
    std::wcout << L"[+] Log kaydedildi: " << filename << L"\n";
}

void ProcessInjectionDetector::ClearResults() { m_results.clear(); }

int ProcessInjectionDetector::GetTotalDetections() const {
    return static_cast<int>(m_results.size());
}