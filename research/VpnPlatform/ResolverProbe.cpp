#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <iostream>
#include <string>
#include <chrono>
#include "DnsFixture.h"

// No custom-server settings, cache flush, injection, or special DNS flags.
int wmain(int argc, wchar_t** argv) {
    if ((argc != 4 && argc != 5) || (std::wstring(argv[2]) != L"A" && std::wstring(argv[2]) != L"AAAA") ||
        (std::wstring(argv[3]) != L"dnsapi" && std::wstring(argv[3]) != L"winsock" && std::wstring(argv[3]) != L"direct")) {
        std::wcerr << L"Usage: Selected.exe <unique.vpn-probe.test> <A|AAAA> <dnsapi|winsock|direct> [start-utc-ms]\n"; return 2;
    }
    const std::wstring name(argv[1]);
    if (!name.ends_with(L".vpn-probe.test") || name.size() > 253) return 2;
    for (auto c : name) if (!((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'-' || c == L'.')) return 2;
    const WORD type = std::wstring(argv[2]) == L"A" ? DNS_TYPE_A : DNS_TYPE_AAAA;
    WSADATA data{}; if (WSAStartup(MAKEWORD(2, 2), &data)) return 3;
    const auto now = [] { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(); };
    if (argc == 5) {
        wchar_t* end{}; const auto start = _wcstoi64(argv[4], &end, 10);
        if (!end || *end || start > now() + 5000) { WSACleanup(); return 2; }
        while (now() < start) Sleep(1);
    }
    DWORD status = 0;
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr, executable, 32768);
    std::wcout << L"exe=\"" << executable << L"\" pid=" << GetCurrentProcessId() << L" utc-ms=" << now() << L" api=" << argv[3] << L" name=" << name << L" type=" << argv[2];
    if (std::wstring(argv[3]) == L"direct") {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) status = WSAGetLastError();
        else {
            DWORD timeout = 3000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            sockaddr_in remote{}; remote.sin_family = AF_INET; remote.sin_port = htons(53);
            InetPtonW(AF_INET, L"198.18.0.53", &remote.sin_addr);
            std::string asciiName; asciiName.reserve(name.size());
            // The command-line validation above permits only ASCII DNS characters.
            for (const auto c : name) asciiName.push_back(static_cast<char>(c));
            const auto q = fixture::query_name(asciiName, type);
            if (connect(s, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) ||
                send(s, reinterpret_cast<const char*>(q.data()), static_cast<int>(q.size()), 0) != static_cast<int>(q.size())) status = WSAGetLastError();
            else {
                std::vector<uint8_t> received(1500);
                const auto count = recv(s, reinterpret_cast<char*>(received.data()), static_cast<int>(received.size()), 0);
                if (count <= 0) status = WSAGetLastError();
                else {
                    received.resize(static_cast<size_t>(count));
                    const auto expected = fixture::answer(q, 10);
                    if (!expected || received != expected->bytes) status = ERROR_INVALID_DATA;
                    else {
                        wchar_t address[INET6_ADDRSTRLEN]{};
                        InetNtopW(type == DNS_TYPE_A ? AF_INET : AF_INET6,
                                  received.data() + received.size() - (type == DNS_TYPE_A ? 4 : 16), address, INET6_ADDRSTRLEN);
                        std::wcout << L" answer=" << address;
                    }
                }
            }
            closesocket(s);
        }
    } else if (std::wstring(argv[3]) == L"dnsapi") {
        PDNS_RECORD records{};
        status = DnsQuery_W(name.c_str(), type, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
        for (auto r = records; r; r = r->pNext) {
            wchar_t address[INET6_ADDRSTRLEN]{};
            if (r->wType == DNS_TYPE_A) InetNtopW(AF_INET, &r->Data.A.IpAddress, address, INET6_ADDRSTRLEN);
            else if (r->wType == DNS_TYPE_AAAA) InetNtopW(AF_INET6, &r->Data.AAAA.Ip6Address, address, INET6_ADDRSTRLEN);
            else continue;
            std::wcout << L" answer=" << address;
        }
        if (records) DnsRecordListFree(records, DnsFreeRecordList);
    } else {
        ADDRINFOW hints{}; hints.ai_family = type == DNS_TYPE_A ? AF_INET : AF_INET6;
        PADDRINFOW result{};
        status = GetAddrInfoW(name.c_str(), nullptr, &hints, &result);
        for (auto r = result; r; r = r->ai_next) {
            wchar_t address[INET6_ADDRSTRLEN]{};
            void* p = r->ai_family == AF_INET ? static_cast<void*>(&reinterpret_cast<sockaddr_in*>(r->ai_addr)->sin_addr)
                                            : static_cast<void*>(&reinterpret_cast<sockaddr_in6*>(r->ai_addr)->sin6_addr);
            InetNtopW(r->ai_family, p, address, INET6_ADDRSTRLEN); std::wcout << L" answer=" << address;
        }
        if (result) FreeAddrInfoW(result);
    }
    std::wcout << L" status=" << status << L'\n'; WSACleanup(); return status ? 1 : 0;
}
