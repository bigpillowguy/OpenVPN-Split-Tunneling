#pragma once
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <algorithm>

// Pure profile construction/validation. No management agent, network or writes.
namespace profile_probe {
using namespace winrt;
using namespace winrt::Windows::Data::Xml::Dom;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Networking;
using namespace winrt::Windows::Networking::Vpn;

struct Config {
    hstring source{L"runtime"}, mode{L"all"}, dns_namespace{L".vpn-probe.test"};
    hstring selected_exe, transport_ip;
};
inline hstring field(XmlDocument const& xml, wchar_t const* name) {
    auto nodes = xml.SelectNodes(hstring(L"/Probe/") + name);
    if (nodes.Size() != 1 || nodes.GetAt(0).InnerText().empty())
        throw hresult_invalid_argument(L"Missing or duplicate laboratory profile field");
    return nodes.GetAt(0).InnerText();
}
inline void validate(Config const& c) {
    if ((c.source != L"runtime" && c.source != L"profile") ||
        (c.mode != L"all" && c.mode != L"selected") ||
        (c.dns_namespace != L".vpn-probe.test" && c.dns_namespace != L"."))
        throw hresult_invalid_argument(L"Unsupported laboratory variant");
    if (c.selected_exe.size() < 4 || c.selected_exe.size() > 1024 ||
        c.selected_exe[1] != L':' || c.selected_exe[2] != L'\\' ||
        std::wstring_view(c.selected_exe).find_first_of(L"\r\n\t") != std::wstring_view::npos)
        throw hresult_invalid_argument(L"SelectedExe must be an absolute drive path");
    if (c.transport_ip.size() > 15 || HostName(c.transport_ip).Type() != HostNameType::Ipv4)
        throw hresult_invalid_argument(L"TransportIp must be a literal IPv4 address");
}
inline Config parse(hstring const& text) {
    if (text.size() > 4096) throw hresult_invalid_argument(L"Laboratory configuration is too large");
    XmlDocument xml; xml.LoadXml(text);
    Config c;
    if (xml.SelectSingleNode(L"/Probe/AssignmentSource")) c.source = field(xml, L"AssignmentSource");
    c.mode = field(xml, L"Mode");
    if (xml.SelectSingleNode(L"/Probe/Namespace")) c.dns_namespace = field(xml, L"Namespace");
    c.selected_exe = field(xml, L"SelectedExe");
    c.transport_ip = field(xml, L"TransportIp");
    validate(c); return c;
}
inline void append(XmlDocument const& xml, wchar_t const* name, hstring const& value) {
    auto node = xml.CreateElement(name); node.InnerText(value);
    xml.DocumentElement().AppendChild(node);
}
inline hstring serialize(Config const& c) {
    validate(c);
    XmlDocument xml; xml.LoadXml(L"<Probe/>");
    append(xml, L"AssignmentSource", c.source); append(xml, L"Mode", c.mode);
    append(xml, L"Namespace", c.dns_namespace); append(xml, L"SelectedExe", c.selected_exe);
    append(xml, L"TransportIp", c.transport_ip);
    return xml.GetXml();
}
inline hstring profile_name(Config const& c) {
    return L"VpnPlatformLab-" + c.source + L"-" + c.mode +
        (c.dns_namespace == L"." ? L"-root" : L"-suffix");
}
inline VpnTrafficFilter filter(Config const& c) {
    VpnTrafficFilter result(VpnAppId(VpnAppIdType::FilePath, c.selected_exe));
    result.Protocol(VpnIPProtocol::None);
    result.RoutingPolicyType(VpnRoutingPolicyType::SplitRouting);
    return result;
}
inline VpnDomainNameInfo name_info(Config const& c) {
    // The WinRT object takes a bare suffix, unlike VPNv2/ProfileXML notation.
    // The special "." root is accepted and exposes a null DomainName getter.
    const auto name = c.dns_namespace == L".vpn-probe.test" ? hstring(L"vpn-probe.test") : c.dns_namespace;
    return VpnDomainNameInfo(name, VpnDomainNameType::Suffix,
        single_threaded_vector<HostName>({HostName(L"198.18.0.53")}), nullptr);
}
inline VpnPlugInProfile make_profile(Config const& c, hstring const& family) {
    validate(c);
    VpnPlugInProfile profile;
    profile.ProfileName(profile_name(c));
    profile.VpnPluginPackageFamilyName(family);
    profile.ServerUris().Append(Uri(L"udp://" + c.transport_ip + L":45999"));
    profile.CustomConfiguration(serialize(c));
    profile.AlwaysOn(false); profile.RememberCredentials(false);
    profile.RequireVpnClientAppUI(false);
    if (c.source == L"profile") {
        profile.DomainNameInfoList().Append(name_info(c));
        if (c.mode == L"selected") profile.TrafficFilters().Append(filter(c));
    }
    // No AppTrigger, default route, SYSTEM/Dnscache exception or proxy.
    return profile;
}
inline bool policy_matches(VpnPlugInProfile const& p, Config const& c, hstring const& family) {
    const bool provisioned = c.source == L"profile";
    const auto expected_filters = provisioned && c.mode == L"selected" ? 1u : 0u;
    if (p.ProfileName() != profile_name(c) || p.VpnPluginPackageFamilyName() != family ||
        p.CustomConfiguration() != serialize(c) || p.AlwaysOn() || p.RememberCredentials() ||
        p.ServerUris().Size() != 1 || p.ServerUris().GetAt(0).Host() != c.transport_ip ||
        p.ServerUris().GetAt(0).SchemeName() != L"udp" || p.ServerUris().GetAt(0).Port() != 45999 ||
        p.AppTriggers().Size() || p.Routes().Size() ||
        p.DomainNameInfoList().Size() != (provisioned ? 1u : 0u) ||
        p.TrafficFilters().Size() != expected_filters) return false;
    if (expected_filters) {
        auto f = p.TrafficFilters().GetAt(0);
        if (!f.AppId() || f.AppId().Type() != VpnAppIdType::FilePath || f.AppId().Value() != c.selected_exe ||
            f.RoutingPolicyType() != VpnRoutingPolicyType::SplitRouting ||
            f.Protocol() != VpnIPProtocol::None || f.AppClaims().Size() ||
            f.LocalAddressRanges().Size() || f.RemoteAddressRanges().Size() ||
            f.LocalPortRanges().Size() || f.RemotePortRanges().Size()) return false;
    }
    if (provisioned) {
        auto n = p.DomainNameInfoList().GetAt(0);
        auto name = n.DomainName();
        auto proxies = n.WebProxyServers();
        auto proxy_uris = n.WebProxyUris();
        const bool correct_name = c.dns_namespace == L"." ? !name : name && name.RawName() == L"vpn-probe.test";
        if (!correct_name || n.DomainNameType() != VpnDomainNameType::Suffix ||
            !n.DnsServers() || n.DnsServers().Size() != 1 || n.DnsServers().GetAt(0).RawName() != L"198.18.0.53" ||
            (proxies && proxies.Size()) || (proxy_uris && proxy_uris.Size())) return false;
    }
    return true;
}
}
