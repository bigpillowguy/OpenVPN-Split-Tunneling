// Compile the exact production parser in this standalone test translation unit.
// Its renamed CLI entry point is never invoked; these tests open no sockets.
#define wmain ProbeMainNotInvokedByCodecTests
#include "DnsProbe.cpp"
#undef wmain
#include <stdexcept>

namespace {
void nameBytes(std::vector<uint8_t>& bytes, const std::string& name) {
    size_t at = 0;
    while (at < name.size()) {
        const auto dot = name.find('.', at);
        const auto end = dot == std::string::npos ? name.size() : dot;
        bytes.push_back(static_cast<uint8_t>(end - at));
        bytes.insert(bytes.end(), name.begin() + static_cast<std::ptrdiff_t>(at), name.begin() + static_cast<std::ptrdiff_t>(end));
        at = end + 1;
    }
    bytes.push_back(0);
}
std::vector<uint8_t> packet(unsigned answers) {
    std::vector<uint8_t> bytes;
    appendWord(bytes, 1); appendWord(bytes, 0x8180); appendWord(bytes, 1);
    appendWord(bytes, static_cast<uint16_t>(answers)); appendWord(bytes, 0); appendWord(bytes, 0);
    nameBytes(bytes, "example.com"); appendWord(bytes, DNS_TYPE_A); appendWord(bytes, 1);
    return bytes;
}
void record(std::vector<uint8_t>& bytes, uint16_t type, const std::vector<uint8_t>& data, const std::string& owner = "") {
    if (owner.empty()) appendWord(bytes, 0xc00c); else nameBytes(bytes, owner);
    appendWord(bytes, type); appendWord(bytes, 1); appendWord(bytes, 0); appendWord(bytes, 60);
    appendWord(bytes, static_cast<uint16_t>(data.size())); bytes.insert(bytes.end(), data.begin(), data.end());
}
unsigned checks = 0;
void expect(const char* label, const std::vector<uint8_t>& bytes, bool valid, unsigned count) {
    unsigned found = 0;
    if (validateResponse(bytes, "example.com", found) != valid || (valid && found != count)) throw std::runtime_error(label);
    ++checks;
}
}

int wmain() {
    try {
        auto a = packet(1); record(a, DNS_TYPE_A, {1, 2, 3, 4});
        expect("positive A", a, true, 1);
        expect("missing answer RR", packet(1), false, 0);
        expect("NOERROR/NODATA", packet(0), true, 0);
        auto nx = packet(0); nx[3] = 0x83;
        expect("NXDOMAIN has no positive A", nx, true, 0);
        auto cn = packet(2); std::vector<uint8_t> target; nameBytes(target, "alias.example.com");
        record(cn, DNS_TYPE_CNAME, target); record(cn, DNS_TYPE_A, {1, 2, 3, 4}, "alias.example.com");
        expect("CNAME to A", cn, true, 1);
        auto bad = packet(1); record(bad, DNS_TYPE_CNAME, {3, 'a'});
        expect("truncated CNAME RDATA", bad, false, 0);
        auto cycle = packet(1); record(cycle, DNS_TYPE_CNAME, {0xc0, 0x0c});
        expect("CNAME alias cycle", cycle, false, 0);
        auto extra = a; extra.push_back(0);
        expect("trailing bytes", extra, false, 0);
        auto shortA = packet(1); record(shortA, DNS_TYPE_A, {1, 2, 3});
        expect("wrong A RDLENGTH", shortA, false, 0);
        auto wrong = a; wrong[13] = 'z';
        expect("wrong question", wrong, false, 0);
        auto missing = packet(2); record(missing, DNS_TYPE_A, {1, 2, 3, 4});
        expect("missing second RR", missing, false, 0);
        auto unrelated = packet(1); record(unrelated, DNS_TYPE_A, {1, 2, 3, 4}, "other.example.com");
        expect("unrelated A is not positive proof", unrelated, true, 0);
        std::cout << "{\"offlineCodecChecks\":" << checks << ",\"status\":\"passed\"}\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << "Offline DNS codec test failed: " << failure.what() << '\n';
        return 1;
    }
}
