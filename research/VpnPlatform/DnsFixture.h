#pragma once
#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// A deliberately small, deterministic laboratory responder. No recursive DNS,
// arbitrary names, compression in questions, fragments, or production traffic.
namespace fixture {
inline uint16_t read16(std::span<const uint8_t> b, size_t p) {
    return static_cast<uint16_t>((b[p] << 8) | b[p + 1]);
}
inline void write16(std::vector<uint8_t>& b, size_t p, uint16_t v) {
    b[p] = static_cast<uint8_t>(v >> 8); b[p + 1] = static_cast<uint8_t>(v);
}
inline void append16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8)); b.push_back(static_cast<uint8_t>(v));
}
struct Answer { std::vector<uint8_t> bytes; std::string name; uint16_t type; };
inline std::optional<Answer> answer(std::span<const uint8_t> q, uint8_t marker) {
    if (q.size() < 17 || q.size() > 1232 || (q[2] & 0xf8) || read16(q, 4) != 1 ||
        read16(q, 6) || read16(q, 8)) return {};
    size_t p = 12;
    std::string name;
    while (p < q.size() && q[p]) {
        const auto n = q[p++];
        if (n > 63 || p + n >= q.size() || name.size() + n + 1 > 254) return {};
        if (!name.empty()) name += '.';
        for (size_t i = 0; i < n; ++i) {
            auto c = q[p++];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return {};
            name += static_cast<char>(c);
        }
    }
    if (p >= q.size() || p + 5 > q.size()) return {};
    ++p;
    const auto type = read16(q, p);
    if (read16(q, p + 2) != 1 || (type != 1 && type != 28) ||
        !name.ends_with(".vpn-probe.test")) return {};
    p += 4;
    // EDNS and other additional query data are not copied into the response.
    std::vector<uint8_t> b(q.begin(), q.begin() + p);
    b[2] = static_cast<uint8_t>(0x80 | (q[2] & 1)); // QR + original RD
    b[3] = 0x80; // RA, NOERROR
    write16(b, 6, 1); write16(b, 8, 0); write16(b, 10, 0);
    append16(b, 0xc00c); append16(b, type); append16(b, 1);
    b.insert(b.end(), {0, 0, 0, 60}); // TTL 60: warm-cache isolation is part of the test.
    if (type == 1) {
        append16(b, 4); b.insert(b.end(), {203, 0, 113, marker});
    } else {
        append16(b, 16);
        b.insert(b.end(), {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, marker});
    }
    return Answer{std::move(b), std::move(name), type};
}
inline uint16_t checksum(std::span<const uint8_t> bytes) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < bytes.size(); i += 2) sum += read16(bytes, i);
    if (bytes.size() & 1) sum += bytes.back() << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}
inline std::optional<Answer> answer_ipv4(std::span<const uint8_t> ip) {
    if (ip.size() < 28 || (ip[0] >> 4) != 4 || ip[9] != 17) return {};
    const size_t ihl = (ip[0] & 15) * 4;
    const size_t total = read16(ip, 2);
    if (ihl < 20 || total > ip.size() || total < ihl + 8 ||
        (read16(ip, 6) & 0x3fff) || read16(ip, ihl + 2) != 53 ||
        !std::equal(ip.begin() + 16, ip.begin() + 20, std::vector<uint8_t>{198, 18, 0, 53}.begin())) return {};
    const size_t udpLength = read16(ip, ihl + 4);
    if (udpLength < 8 || ihl + udpLength != total) return {};
    auto a = answer(ip.subspan(ihl + 8, udpLength - 8), 10);
    if (!a) return {};
    std::vector<uint8_t> b(28, 0);
    b[0] = 0x45; b[8] = 64; b[9] = 17;
    write16(b, 2, static_cast<uint16_t>(28 + a->bytes.size()));
    std::copy_n(ip.begin() + 16, 4, b.begin() + 12);
    std::copy_n(ip.begin() + 12, 4, b.begin() + 16);
    write16(b, 10, checksum(std::span(b).first(20)));
    write16(b, 20, 53); write16(b, 22, read16(ip, ihl));
    write16(b, 24, static_cast<uint16_t>(8 + a->bytes.size()));
    // UDP checksum zero is permitted for IPv4. TCP/IPv6 transport are not modeled.
    b.insert(b.end(), a->bytes.begin(), a->bytes.end());
    a->bytes = std::move(b);
    return a;
}
inline std::vector<uint8_t> query_name(std::string_view name, uint16_t type = 1) {
    std::vector<uint8_t> q{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    while (!name.empty()) {
        const auto dot = name.find('.');
        const auto label = name.substr(0, dot);
        if (label.empty() || label.size() > 63 || q.size() + label.size() > 266) return {};
        q.push_back(static_cast<uint8_t>(label.size())); q.insert(q.end(), label.begin(), label.end());
        if (dot == std::string_view::npos) break;
        name.remove_prefix(dot + 1);
    }
    q.push_back(0); append16(q, type); append16(q, 1); return q;
}
inline std::vector<uint8_t> query(uint16_t type = 1) { return query_name("test.vpn-probe.test", type); }
}
