#include "ProfileConfig.h"
#include <iostream>
#include <stdexcept>

int main() {
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    int checks = 0;
    auto require = [&](bool ok) { ++checks; if (!ok) throw std::runtime_error("profile check failed"); };
    auto rejects = [&](profile_probe::Config const& c) {
        try { profile_probe::validate(c); } catch (winrt::hresult_error const&) { return true; }
        return false;
    };
    try {
        const winrt::hstring family(L"VpnPlatformResearch_offlinetest");
        for (auto source : {L"runtime", L"profile"}) for (auto mode : {L"all", L"selected"})
        for (auto ns : {L".vpn-probe.test", L"."}) {
            profile_probe::Config c{source, mode, ns, L"C:\\Lab & Tests\\Selected.exe", L"192.0.2.1"};
            const auto parsed = profile_probe::parse(profile_probe::serialize(c));
            require(parsed.source == c.source && parsed.mode == c.mode && parsed.dns_namespace == c.dns_namespace);
            require(parsed.selected_exe == c.selected_exe && parsed.transport_ip == c.transport_ip);
            auto p = profile_probe::make_profile(c, family);
            require(profile_probe::policy_matches(p, c, family));
            require(p.ServerUris().Size() == 1 && p.ServerUris().GetAt(0).Host() == c.transport_ip);
            p.TrafficFilters().Append(profile_probe::filter(c));
            require(!profile_probe::policy_matches(p, c, family));
        }
        profile_probe::Config c{L"profile", L"selected", L".vpn-probe.test", L"C:\\Lab\\Selected.exe", L"192.0.2.1"};
        auto p = profile_probe::make_profile(c, family);
        p.TrafficFilters().GetAt(0).AppId().Value(L"C:\\Lab\\Unselected.exe");
        require(!profile_probe::policy_matches(p, c, family));
        p = profile_probe::make_profile(c, family);
        p.DomainNameInfoList().GetAt(0).DnsServers().Append(winrt::Windows::Networking::HostName(L"127.0.0.53"));
        require(!profile_probe::policy_matches(p, c, family));
        p = profile_probe::make_profile(c, family);
        p.ServerUris().SetAt(0, winrt::Windows::Foundation::Uri(L"https://192.0.2.1:45999"));
        require(!profile_probe::policy_matches(p, c, family));
        p = profile_probe::make_profile(c, family);
        p.ServerUris().SetAt(0, winrt::Windows::Foundation::Uri(L"udp://192.0.2.1:46000"));
        require(!profile_probe::policy_matches(p, c, family));
        auto bad = c; bad.source = L"mixed"; require(rejects(bad));
        bad = c; bad.mode = L"SYSTEM"; require(rejects(bad));
        bad = c; bad.dns_namespace = L"example.com"; require(rejects(bad));
        bad = c; bad.selected_exe = L"Selected.exe"; require(rejects(bad));
        bad = c; bad.transport_ip = L"vpn.example.com"; require(rejects(bad));
        bad = c; bad.transport_ip = L"::1"; require(rejects(bad));
        bool duplicate_rejected = false;
        try { (void)profile_probe::parse(L"<Probe><Mode>all</Mode><Mode>selected</Mode><SelectedExe>C:\\Lab\\Selected.exe</SelectedExe><TransportIp>192.0.2.1</TransportIp></Probe>"); }
        catch (winrt::hresult_error const&) { duplicate_rejected = true; }
        require(duplicate_rejected);
        std::cout << checks << " offline profile checks passed. No management agent, profile registration or network opened.\n";
    } catch (winrt::hresult_error const& e) {
        std::wcerr << L"Offline profile error: " << e.message().c_str() << L'\n'; return 1;
    }
}
