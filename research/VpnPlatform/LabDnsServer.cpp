#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "DnsFixture.h"
#include <iostream>

// VM-only system-DNS control. Exclusive bind; never changes system DNS itself.
int main(int argc, char** argv) {
    if (argc != 2 || std::string(argv[1]) != "--serve-vm-control") {
        std::cerr << "VM-only: LabDnsServer.exe --serve-vm-control (127.0.0.53:53)\n"; return 2;
    }
    WSADATA data{}; if (WSAStartup(MAKEWORD(2, 2), &data)) return 3;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 3;
    BOOL exclusive = TRUE;
    if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive))) return 3;
    sockaddr_in local{}; local.sin_family = AF_INET; local.sin_port = htons(53);
    inet_pton(AF_INET, "127.0.0.53", &local.sin_addr);
    if (bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local))) {
        std::cerr << "Exclusive bind failed: " << WSAGetLastError() << '\n'; closesocket(s); WSACleanup(); return 3;
    }
    std::cout << "Control DNS ready on 127.0.0.53:53; *.vpn-probe.test -> .20; Ctrl+C stops.\n" << std::flush;
    for (;;) {
        uint8_t bytes[2048]; sockaddr_in peer{}; int peerSize = sizeof(peer);
        const int n = recvfrom(s, reinterpret_cast<char*>(bytes), sizeof(bytes), 0, reinterpret_cast<sockaddr*>(&peer), &peerSize);
        if (n <= 0) break;
        auto answer = fixture::answer(std::span(bytes, static_cast<size_t>(n)), 20);
        if (!answer) continue;
        sendto(s, reinterpret_cast<const char*>(answer->bytes.data()), static_cast<int>(answer->bytes.size()), 0,
               reinterpret_cast<const sockaddr*>(&peer), peerSize);
        std::cout << "CONTROL " << answer->name << " type=" << answer->type << '\n' << std::flush;
    }
    closesocket(s); WSACleanup();
}
