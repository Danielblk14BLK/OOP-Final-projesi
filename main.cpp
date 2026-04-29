// ============================================================
// main.cpp
// Process Injection Tespit Aracı - Giriş Noktası
// ============================================================

#include <fcntl.h>
#include <io.h>
#include "ProcessInjectionDetector.h"

void PrintBanner() {
    std::wcout << L"\n";
    std::wcout << L"  =========================================\n";
    std::wcout << L"   PROCESS INJECTION TESPIT ARACI v1.0\n";
    std::wcout << L"   Defensive Reverse Engineering\n";
    std::wcout << L"  =========================================\n\n";
}

void PrintMenu() {
    std::wcout << L"\n=== MENU ===\n";
    std::wcout << L"  [1] Tüm süreçleri tara\n";
    std::wcout << L"  [2] Belirli PID'i tara\n";
    std::wcout << L"  [3] Sonuçları göster\n";
    std::wcout << L"  [4] Log dosyasına kaydet\n";
    std::wcout << L"  [5] Sonuçları temizle\n";
    std::wcout << L"  [0] Çıkış\n";
    std::wcout << L"\nSeçiminiz: ";
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

int main() {
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U16TEXT);
    PrintBanner();

    if (!IsRunningAsAdmin()) {
        std::wcout << L"[UYARI] Yönetici yetkisi gerekli! Bazı süreçler taranamayabilir.\n\n";
    }
    else {
        std::wcout << L"[+] Yönetici yetkisiyle çalışıyor.\n\n";
    }

    ProcessInjectionDetector detector;
    int choice = -1;

    while (choice != 0) {
        PrintMenu();
        std::wcin >> choice;

        switch (choice) {
        case 1:
            detector.ScanAllProcesses();
            detector.PrintResults();
            break;

        case 2: {
            DWORD pid = 0;
            std::wcout << L"PID girin: ";
            std::wcin >> pid;
            if (pid > 0) {
                detector.ScanProcess(pid);
                detector.PrintResults();
            }
            else {
                std::wcout << L"[HATA] Geçersiz PID!\n";
            }
            break;
        }

        case 3:
            detector.PrintResults();
            break;

        case 4: {
            SYSTEMTIME st;
            GetLocalTime(&st);
            wchar_t ts[64];
            swprintf_s(ts, L"injection_log_%04d%02d%02d_%02d%02d%02d.txt",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
            detector.SaveLog(ts);
            break;
        }

        case 5:
            detector.ClearResults();
            std::wcout << L"[+] Sonuçlar temizlendi.\n";
            break;

        case 0:
            std::wcout << L"\n[+] Program sonlandırılıyor...\n";
            break;

        default:
            std::wcout << L"[HATA] Geçersiz seçim!\n";
            break;
        }
    }

    return 0;
}