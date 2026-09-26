#include "DnsFixture.h"
#include <iostream>
#include <stdexcept>

int main() {
    int checks = 0;
    auto require = [&](bool condition) { ++checks; if (!condition) throw std::runtime_error("fixture check failed"); };
    const auto q = fixture::query();
    auto a = fixture::answer(q, 10);
    require(a && a->bytes.back() == 10 && fixture::read16(a->bytes, 6) == 1);
    require(a->name == "test.vpn-probe.test" && a->type == 1);
    auto b = fixture::answer(q, 20);
    require(b && b->bytes.back() == 20 && a->bytes != b->bytes);
    auto six = fixture::answer(fixture::query(28), 10);
    require(six && fixture::read16(six->bytes, six->bytes.size() - 18) == 16);
    for (size_t i = 0; i < q.size(); ++i) require(!fixture::answer(std::span(q).first(i), 10));
    auto bad = q; bad[12] = 0xc0; require(!fixture::answer(bad, 10));
    bad = q; bad[2] |= 0x80; require(!fixture::answer(bad, 10));
    bad = q; bad[5] = 2; require(!fixture::answer(bad, 10));
    bad = q; bad[20] = '_'; require(!fixture::answer(bad, 10));
    require(!fixture::answer(fixture::query(255), 10));
    std::vector<uint8_t> ip(28, 0); ip[0] = 0x45; ip[9] = 17;
    ip[12] = 198; ip[13] = 18; ip[15] = 2;
    ip[16] = 198; ip[17] = 18; ip[19] = 53;
    fixture::write16(ip, 2, static_cast<uint16_t>(28 + q.size()));
    fixture::write16(ip, 20, 12345); fixture::write16(ip, 22, 53);
    fixture::write16(ip, 24, static_cast<uint16_t>(8 + q.size())); ip.insert(ip.end(), q.begin(), q.end());
    auto response = fixture::answer_ipv4(ip);
    require(response && fixture::checksum(std::span(response->bytes).first(20)) == 0);
    require(response->bytes[15] == 53 && response->bytes[19] == 2);
    require(fixture::read16(response->bytes, 20) == 53 && fixture::read16(response->bytes, 22) == 12345);
    bad = ip; bad[6] = 0x20; require(!fixture::answer_ipv4(bad));
    bad = ip; bad[19] = 54; require(!fixture::answer_ipv4(bad));
    bad = ip; bad[24] = 0xff; require(!fixture::answer_ipv4(bad));
    std::cout << checks << " offline fixture checks passed. No sockets or VPN opened.\n";
}
