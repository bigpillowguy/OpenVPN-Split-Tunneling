#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <bcrypt.h>
#include <cstdint>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {
struct Result {
    std::string mode = "invalid", query, kind = "input";
    DWORD status = ERROR_INVALID_PARAMETER;
    std::optional<unsigned> rcode, answers, addresses;
    std::optional<bool> idValid, responseValid, truncated;
};
struct Socket {
    SOCKET value = INVALID_SOCKET;
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};
uint16_t word(const std::vector<uint8_t>& bytes, size_t at) {
    return static_cast<uint16_t>((static_cast<unsigned>(bytes[at]) << 8) | bytes[at + 1]);
}
void appendWord(std::vector<uint8_t>& bytes, uint16_t value) {
    bytes.push_back(static_cast<uint8_t>(value >> 8)); bytes.push_back(static_cast<uint8_t>(value));
}
bool waitSocket(SOCKET socket, bool read, ULONGLONG deadline, DWORD& error, bool connecting = false) {
    const auto now = GetTickCount64();
    if (now >= deadline) { error = WSAETIMEDOUT; return false; }
    const auto remaining = deadline - now;
    timeval timeout{static_cast<long>(remaining / 1000), static_cast<long>((remaining % 1000) * 1000)};
    fd_set set{}; FD_ZERO(&set); FD_SET(socket, &set);
    fd_set exceptions = set;
    const int ready = select(0, read ? &set : nullptr, read ? nullptr : &set, connecting ? &exceptions : nullptr, &timeout);
    if (ready > 0) return true;
    error = ready == 0 ? WSAETIMEDOUT : static_cast<DWORD>(WSAGetLastError()); return false;
}
bool sendBytes(SOCKET socket, const std::vector<uint8_t>& bytes, bool stream, ULONGLONG deadline, DWORD& error) {
    size_t sent = 0;
    while (sent < bytes.size()) {
        if (!waitSocket(socket, false, deadline, error)) return false;
        const int count = send(socket, reinterpret_cast<const char*>(bytes.data() + sent), static_cast<int>(bytes.size() - sent), 0);
        if (count == SOCKET_ERROR) { error = WSAGetLastError(); if (error == WSAEWOULDBLOCK) continue; return false; }
        if (count == 0 || (!stream && static_cast<size_t>(count) != bytes.size())) { error = WSAEMSGSIZE; return false; }
        sent += static_cast<size_t>(count);
    }
    return true;
}
bool receiveExact(SOCKET socket, std::vector<uint8_t>& bytes, ULONGLONG deadline, DWORD& error) {
    size_t received = 0;
    while (received < bytes.size()) {
        if (!waitSocket(socket, true, deadline, error)) return false;
        const int count = recv(socket, reinterpret_cast<char*>(bytes.data() + received), static_cast<int>(bytes.size() - received), 0);
        if (count == SOCKET_ERROR) { error = WSAGetLastError(); if (error == WSAEWOULDBLOCK) continue; return false; }
        if (count == 0) { error = WSAECONNRESET; return false; }
        received += static_cast<size_t>(count);
    }
    return true;
}
bool readName(const std::vector<uint8_t>& bytes, size_t& next, std::string& name) {
    size_t cursor = next, encodedEnd = 0; unsigned hops = 0; name.clear();
    while (cursor < bytes.size() && ++hops <= 128) {
        const unsigned count = bytes[cursor++];
        if ((count & 0xc0) == 0xc0) {
            if (cursor >= bytes.size()) return false;
            if (!encodedEnd) encodedEnd = cursor + 1;
            cursor = ((count & 0x3f) << 8) | bytes[cursor]; continue;
        }
        if (count > 63 || cursor + count > bytes.size()) return false;
        if (!count) {
            next = encodedEnd ? encodedEnd : cursor;
            return true;
        }
        if (!name.empty()) name.push_back('.');
        for (unsigned i = 0; i < count; ++i) {
            char c = static_cast<char>(bytes[cursor++]);
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            name.push_back(c);
        }
        if (name.size() > 253) return false;
    }
    return false;
}
bool validateResponse(const std::vector<uint8_t>& bytes, const std::string& expected, unsigned& addresses) {
    size_t cursor = 12; std::string name;
    if (!readName(bytes, cursor, name) || name != expected || cursor + 4 > bytes.size() ||
        word(bytes, cursor) != DNS_TYPE_A || word(bytes, cursor + 2) != 1) return false;
    cursor += 4;
    const unsigned answers = word(bytes, 6);
    const unsigned total = answers + word(bytes, 8) + word(bytes, 10);
    std::map<std::string, std::string> aliases;
    std::map<std::string, unsigned> aRecords;
    for (unsigned i = 0; i < total; ++i) {
        if (!readName(bytes, cursor, name) || cursor + 10 > bytes.size()) return false;
        const auto type = word(bytes, cursor), recordClass = word(bytes, cursor + 2), length = word(bytes, cursor + 8);
        cursor += 10;
        const auto end = cursor + length;
        if (end > bytes.size()) return false;
        if (recordClass == 1 && type == DNS_TYPE_A) {
            if (length != 4) return false;
            if (i < answers) ++aRecords[name];
        } else if (recordClass == 1 && type == DNS_TYPE_CNAME) {
            std::string target;
            if (!readName(bytes, cursor, target) || cursor != end) return false;
            if (i < answers && !aliases.emplace(name, target).second) return false;
        }
        cursor = end;
    }
    if (cursor != bytes.size()) return false;
    std::set<std::string> visited;
    name = expected;
    while (visited.insert(name).second) {
        if (const auto found = aRecords.find(name); found != aRecords.end()) { addresses = found->second; return true; }
        const auto alias = aliases.find(name);
        if (alias == aliases.end()) return true; // Valid NOERROR/NODATA has no positive address proof.
        name = alias->second;
    }
    return false;
}
void rawQuery(Result& result, const wchar_t* resolver) {
    result.kind = "winsock"; result.status = 0;
    sockaddr_in remote{}; remote.sin_family = AF_INET; remote.sin_port = htons(53);
    if (InetPtonW(AF_INET, resolver, &remote.sin_addr) != 1) { result.kind = "input"; result.status = ERROR_INVALID_PARAMETER; return; }
    const uint32_t ip = ntohl(remote.sin_addr.s_addr);
    if (ip == 0 || ip == 0xffffffff || (ip >> 28) >= 14) { result.kind = "input"; result.status = ERROR_INVALID_PARAMETER; return; }
    uint16_t id{};
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&id), sizeof(id), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        result.kind = "win32"; result.status = ERROR_GEN_FAILURE; return;
    }
    std::vector<uint8_t> query;
    appendWord(query, id); appendWord(query, 0x0100); appendWord(query, 1);
    appendWord(query, 0); appendWord(query, 0); appendWord(query, 0);
    size_t start = 0;
    while (start < result.query.size()) {
        const auto dot = result.query.find('.', start);
        const auto end = dot == std::string::npos ? result.query.size() : dot;
        query.push_back(static_cast<uint8_t>(end - start));
        query.insert(query.end(), result.query.begin() + static_cast<std::ptrdiff_t>(start), result.query.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }
    query.push_back(0); appendWord(query, DNS_TYPE_A); appendWord(query, 1);
    const bool tcp = result.mode == "tcp";
    Socket socket{::socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP)};
    if (socket.value == INVALID_SOCKET) { result.status = WSAGetLastError(); return; }
    u_long nonblocking = 1;
    if (ioctlsocket(socket.value, FIONBIO, &nonblocking)) { result.status = WSAGetLastError(); return; }
    const auto deadline = GetTickCount64() + 2000;
    if (connect(socket.value, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) == SOCKET_ERROR) {
        result.status = WSAGetLastError();
        if (result.status != WSAEWOULDBLOCK && result.status != WSAEINPROGRESS) return;
        if (!waitSocket(socket.value, false, deadline, result.status, true)) return;
        int connectError = 0, length = sizeof(connectError);
        if (getsockopt(socket.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&connectError), &length)) { result.status = WSAGetLastError(); return; }
        if (connectError) { result.status = static_cast<DWORD>(connectError); return; }
        result.status = 0;
    }
    auto outgoing = query;
    if (tcp) { outgoing.clear(); appendWord(outgoing, static_cast<uint16_t>(query.size())); outgoing.insert(outgoing.end(), query.begin(), query.end()); }
    if (!sendBytes(socket.value, outgoing, tcp, deadline, result.status)) return;
    std::vector<uint8_t> response;
    if (tcp) {
        std::vector<uint8_t> prefix(2);
        if (!receiveExact(socket.value, prefix, deadline, result.status)) return;
        response.resize(word(prefix, 0));
        if (response.size() < 12) { result.kind = "win32"; result.status = ERROR_INVALID_DATA; return; }
        if (!receiveExact(socket.value, response, deadline, result.status)) return;
    } else {
        response.resize(65535);
        for (;;) {
            if (!waitSocket(socket.value, true, deadline, result.status)) return;
            const int count = recv(socket.value, reinterpret_cast<char*>(response.data()), static_cast<int>(response.size()), 0);
            if (count == SOCKET_ERROR) { result.status = WSAGetLastError(); if (result.status == WSAEWOULDBLOCK) continue; return; }
            response.resize(static_cast<size_t>(count)); break;
        }
    }
    result.status = 0;
    result.addresses = 0;
    result.idValid = response.size() >= 2 && word(response, 0) == id;
    result.responseValid = response.size() >= 12 && *result.idValid && (word(response, 2) & 0xf800) == 0x8000 &&
        word(response, 4) == 1 && validateResponse(response, result.query, *result.addresses);
    if (response.size() >= 12) { result.rcode = word(response, 2) & 15; result.answers = word(response, 6); result.truncated = (word(response, 2) & 0x200) != 0; }
    if (!*result.responseValid) { result.kind = "win32"; result.status = ERROR_INVALID_DATA; }
}
template<class T> void nullable(const std::optional<T>& value) { if (value) std::cout << *value; else std::cout << "null"; }
}

int wmain(int argc, wchar_t** argv) {
    const auto began = GetTickCount64(); Result result;
    if (argc >= 3) {
        const std::wstring mode(argv[1]), query(argv[2]);
        const bool raw = mode == L"udp" || mode == L"tcp";
        if ((raw ? argc == 4 : argc == 3) && (raw || mode == L"getaddrinfo" || mode == L"dns-standard" || mode == L"dns-wire") &&
            (query == L"browserleaks.com" || query == L"example.com")) {
            // Both strings have passed an exact ASCII whitelist above.
            result.mode.clear(); for (wchar_t c : mode) result.mode.push_back(static_cast<char>(c));
            for (wchar_t c : query) result.query.push_back(static_cast<char>(c)); result.status = 0;
            WSADATA data{}; const int init = WSAStartup(MAKEWORD(2, 2), &data);
            if (init) { result.kind = "winsock"; result.status = static_cast<DWORD>(init); }
            else {
                if (raw) rawQuery(result, argv[3]);
                else if (mode == L"getaddrinfo") {
                    result.kind = "gai"; ADDRINFOW hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
                    PADDRINFOW addresses{}; result.status = static_cast<DWORD>(GetAddrInfoW(query.c_str(), nullptr, &hints, &addresses));
                    result.answers = 0; for (auto item = addresses; item; item = item->ai_next) ++*result.answers;
                    result.addresses = result.answers;
                    if (addresses) FreeAddrInfoW(addresses);
                } else {
                    result.kind = "dns"; PDNS_RECORD records{};
                    const DWORD flags = mode == L"dns-wire" ? DNS_QUERY_WIRE_ONLY | DNS_QUERY_TREAT_AS_FQDN : DNS_QUERY_STANDARD;
                    result.status = static_cast<DWORD>(DnsQuery_W(query.c_str(), DNS_TYPE_A, flags, nullptr, &records, nullptr));
                    result.answers = 0; result.addresses = 0;
                    for (auto item = records; item; item = item->pNext) { ++*result.answers; if (item->wType == DNS_TYPE_A) ++*result.addresses; }
                    if (records) DnsRecordListFree(records, DnsFreeRecordList);
                }
                WSACleanup();
            }
        }
    }
    const bool ok = result.status == 0 && (!result.rcode || *result.rcode == 0) && result.addresses.value_or(0) > 0 && !result.truncated.value_or(false);
    std::cout << std::boolalpha << "{\"version\":1,\"mode\":\"" << result.mode << "\",\"query\":\"" << result.query
        << "\",\"statusKind\":\"" << result.kind << "\",\"status\":" << result.status << ",\"elapsedMs\":" << GetTickCount64() - began
        << ",\"rcode\":"; nullable(result.rcode); std::cout << ",\"answerCount\":"; nullable(result.answers);
    std::cout << ",\"idValid\":"; nullable(result.idValid); std::cout << ",\"responseValid\":"; nullable(result.responseValid);
    std::cout << ",\"addressCount\":"; nullable(result.addresses); std::cout << ",\"truncated\":"; nullable(result.truncated);
    std::cout << ",\"ok\":" << ok << "}\n";
    return result.kind == "input" ? 2 : ok ? 0 : 1;
}
