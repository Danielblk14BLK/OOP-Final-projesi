#pragma once
// ============================================================
// ProcessInjectionDetector.h
// Process Injection Tespit Aracı - Başlık Dosyası
// Konu : Defensive Reverse Engineering - Process Injection Detection
// ============================================================

#ifndef PROCESS_INJECTION_DETECTOR_H
#define PROCESS_INJECTION_DETECTOR_H

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ctime>
#include <iomanip>

#pragma comment(lib, "Psapi.lib")

// ============================================================
// Veri Yapıları (Data Structures)
// ============================================================

struct SuspiciousModule {
    std::wstring moduleName;
    std::wstring modulePath;
    DWORD processId;
    std::wstring processName;
    std::wstring reason;
    std::wstring injectionType;
};

struct SuspiciousMemoryRegion {
    DWORD processId;
    std::wstring processName;
    PVOID baseAddress;
    SIZE_T regionSize;
    DWORD protect;
    DWORD type;
    std::wstring reason;
};

struct SuspiciousThread {
    DWORD threadId;
    DWORD ownerProcessId;
    std::wstring processName;
    PVOID startAddress;
    std::wstring reason;
};

struct DetectionResult {
    bool injectionDetected;
    std::wstring processName;
    DWORD processId;
    std::wstring injectionType;
    std::wstring description;
    std::wstring severity;
    std::wstring timestamp;
};

// ============================================================
// Ana Dedektör Sınıfı
// ============================================================
class ProcessInjectionDetector {
public:
    ProcessInjectionDetector();
    ~ProcessInjectionDetector();

    void ScanAllProcesses();
    void ScanProcess(DWORD pid);
    void PrintResults();
    void SaveLog(const std::wstring& filename);
    void ClearResults();
    int  GetTotalDetections() const;

private:
    void DetectDLLInjection(DWORD pid, const std::wstring& processName);
    void DetectProcessHollowing(DWORD pid, const std::wstring& processName);
    void DetectShellcodeInjection(DWORD pid, const std::wstring& processName);
    void DetectRemoteThreads(DWORD pid, const std::wstring& processName);
    void DetectAPCInjection(DWORD pid, const std::wstring& processName);

    std::wstring GetProcessName(DWORD pid);
    std::wstring GetCurrentTimestamp();
    bool IsSystemProcess(const std::wstring& name);
    bool IsPathSuspicious(const std::wstring& path);
    bool IsModuleSignedOrKnown(const std::wstring& path);
    PVOID GetThreadStartAddress(HANDLE hThread);
    std::wstring ProtectFlagsToString(DWORD protect);

    std::vector<DetectionResult> m_results;
    std::vector<std::wstring>    m_suspiciousPaths;
    std::vector<std::wstring>    m_knownGoodPaths;
    bool m_verbose;
};

#endif // PROCESS_INJECTION_DETECTOR_H
