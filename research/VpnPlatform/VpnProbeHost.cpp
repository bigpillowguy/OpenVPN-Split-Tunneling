#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <robuffer.h>
#include <winrt/Windows.ApplicationModel.Background.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Storage.Streams.h>
#include <mutex>
#include "DnsFixture.h"
#include "ProfileConfig.h"

using namespace winrt;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::ApplicationModel::Background;
using namespace winrt::Windows::ApplicationModel::Core;
using namespace winrt::Windows::Networking;
using namespace winrt::Windows::Networking::Sockets;
using namespace winrt::Windows::Networking::Vpn;
using namespace winrt::Windows::Storage;
using namespace winrt::Windows::Storage::Streams;
using namespace winrt::Windows::Data::Xml::Dom;

namespace {
void trace(hstring const& message) noexcept {
    // Only laboratory query names and lifecycle events; no traffic/profile dump.
    try {
        static std::mutex lock;
        std::scoped_lock guard(lock);
        auto file = ApplicationData::Current().LocalFolder().CreateFileAsync(
            L"vpn-probe.log", CreationCollisionOption::OpenIfExists).get();
        FileIO::AppendTextAsync(file, message + L"\r\n").get();
    } catch (...) {}
}
uint8_t* data(IBuffer const& buffer) {
    uint8_t* p{};
    check_hresult(buffer.as<::Windows::Storage::Streams::IBufferByteAccess>()->Buffer(&p));
    return p;
}
struct Plugin : implements<Plugin, IVpnPlugIn> {
    DatagramSocket transport{nullptr};
    void Connect(VpnChannel const& channel) {
        try {
            const auto config = profile_probe::parse(channel.Configuration().CustomField());
            const auto mode = config.mode;
            const HostName transportAddress(config.transport_ip);

            transport = DatagramSocket();
            // Native VPN platform sequence: associate, connect outer transport,
            // then start the channel. UDP Connect does not require a VPN server.
            channel.AssociateTransport(transport, nullptr);
            transport.ConnectAsync(transportAddress, L"45999").get();

            VpnRouteAssignment routes;
            routes.Ipv4InclusionRoutes(single_threaded_vector<VpnRoute>({VpnRoute(HostName(L"198.18.0.53"), 32)}));
            routes.ExcludeLocalSubnets(false);
            VpnDomainNameAssignment names{nullptr};
            VpnTrafficFilterAssignment filters;
            if (config.source == L"runtime") {
                names = VpnDomainNameAssignment();
                names.DomainNameList().Append(profile_probe::name_info(config));
                if (mode == L"selected") filters.TrafficFilterList().Append(profile_probe::filter(config));
            }
            auto addresses = single_threaded_vector<HostName>({HostName(L"198.18.0.2")});
            // No default route or explicit Dnscache allow rule: adding one
            // would contaminate the selected-application question being tested.
            if (config.source == L"runtime" && mode == L"selected") {
                channel.StartWithTrafficFilter(addresses.GetView(), nullptr, nullptr,
                    routes, names, 1400, 1500, false, transport, nullptr, filters);
            } else {
                channel.StartWithMainTransport(addresses.GetView(), nullptr, nullptr,
                    routes, names, 1400, 1500, false, transport);
            }
            trace(L"CONNECTED mode=" + mode + L" source=" + config.source + L" namespace=" + config.dns_namespace);
        } catch (hresult_error const& e) {
            trace(L"CONNECT_ERROR " + to_hstring(static_cast<uint32_t>(e.code().value)) + L" " + e.message());
            throw;
        }
    }
    void Disconnect(VpnChannel const& channel) {
        channel.Stop(); transport = nullptr; trace(L"DISCONNECTED");
    }
    void Encapsulate(VpnChannel const& channel, VpnPacketBufferList const& packets, VpnPacketBufferList const&) {
        while (packets.Size()) {
            auto packet = packets.RemoveAtBegin();
            auto buffer = packet.Buffer();
            auto answer = fixture::answer_ipv4(std::span(data(buffer), buffer.Length()));
            if (!answer) { trace(L"DROP_NON_FIXTURE_PACKET"); continue; }
            auto response = channel.GetVpnReceivePacketBuffer();
            auto target = response.Buffer();
            if (answer->bytes.size() > target.Capacity()) throw hresult_error(E_BOUNDS);
            std::copy(answer->bytes.begin(), answer->bytes.end(), data(target));
            target.Length(static_cast<uint32_t>(answer->bytes.size()));
            channel.AppendVpnReceivePacketBuffer(response);
            trace(L"VPN " + to_hstring(answer->name) + L" type=" + to_hstring(answer->type));
        }
        channel.FlushVpnReceivePacketBuffers();
    }
    void Decapsulate(VpnChannel const&, VpnPacketBuffer const&, VpnPacketBufferList const&, VpnPacketBufferList const&) {
        // No external datagram is trusted as an IP packet by this fixture.
    }
    void GetKeepAlivePayload(VpnChannel const&, VpnPacketBuffer& buffer) { buffer = nullptr; }
};
struct Task : implements<Task, IBackgroundTask> {
    void Run(IBackgroundTaskInstance const& instance) {
        auto deferral = instance.GetDeferral();
        try {
            // Keep the same plugin alive across Connect/Encapsulate/Disconnect.
            static const auto plugin = make<Plugin>();
            VpnChannel::ProcessEventAsync(plugin, instance.TriggerDetails());
        } catch (hresult_error const& e) {
            trace(L"TASK_ERROR " + to_hstring(static_cast<uint32_t>(e.code().value)) + L" " + e.message());
        } catch (...) { trace(L"TASK_ERROR unknown"); }
        deferral.Complete();
    }
};
struct Factory : implements<Factory, IActivationFactory> {
    IInspectable ActivateInstance() { return make<Task>(); }
};
struct Factories : implements<Factories, IGetActivationFactory> {
    IInspectable GetActivationFactory(hstring const& id) {
        if (id == L"VpnPlatform.ProbeTask") return make<Factory>();
        throw hresult_class_not_available();
    }
};
}
#ifdef PROBE_DLL
extern "C" HRESULT __stdcall ProbeGetActivationFactory(void* id, void** factory) noexcept {
    if (!factory) return E_POINTER;
    *factory = nullptr;
    try {
        hstring name;
        copy_from_abi(name, id);
        if (name != L"VpnPlatform.ProbeTask") return CLASS_E_CLASSNOTAVAILABLE;
        *factory = detach_abi(make<Factory>()); return S_OK;
    } catch (...) { return to_hresult(); }
}
extern "C" HRESULT __stdcall ProbeCanUnloadNow() noexcept {
    return get_module_lock() ? S_FALSE : S_OK;
}
#else
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    init_apartment(apartment_type::multi_threaded);
    try { CoreApplication::RunWithActivationFactories(make<Factories>()); }
    catch (hresult_error const& e) { trace(L"HOST_ERROR " + e.message()); return 1; }
    return 0;
}
#endif
