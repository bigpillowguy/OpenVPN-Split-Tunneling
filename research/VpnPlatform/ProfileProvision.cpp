#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.ApplicationModel.Activation.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.UI.Core.h>
#include "ProfileConfig.h"

using namespace winrt;
using namespace Windows::ApplicationModel;
using namespace Windows::ApplicationModel::Activation;
using namespace Windows::ApplicationModel::Core;
using namespace Windows::Foundation;
using namespace Windows::Networking::Vpn;
using namespace Windows::Storage;
using namespace Windows::UI::Core;

// Activated explicitly inside the disposable VM. Capability and package identity
// come from this package; no unrestricted desktop call to VpnManagementAgent.
struct Provision : implements<Provision, IFrameworkViewSource, IFrameworkView> {
    CoreWindow window{nullptr};
    bool started = false;
    IFrameworkView CreateView() { return *this; }
    void Initialize(CoreApplicationView const& view) {
        view.Activated([this](auto const&, IActivatedEventArgs const& args) {
            if (started) return;
            started = true;
            window.Activate();
            auto launch = args.try_as<ILaunchActivatedEventArgs>();
            provision(launch ? launch.Arguments() : hstring{});
        });
    }
    void SetWindow(CoreWindow const& value) { window = value; }
    void Load(hstring const&) {}
    void Uninitialize() {}
    void Run() { window.Dispatcher().ProcessEvents(CoreProcessEventsOption::ProcessUntilQuit); }
    fire_and_forget provision(hstring request) {
        auto lifetime = get_strong();
        hstring result = L"ERROR: request was not processed";
        hstring request_id{L"unvalidated"};
        try {
            Windows::Data::Xml::Dom::XmlDocument xml;
            if (request.size() > 4096) throw hresult_invalid_argument(L"Request too large");
            xml.LoadXml(request);
            if (profile_probe::field(xml, L"VmAcknowledged") != L"InsideDisposableVm")
                throw hresult_invalid_argument(L"Explicit disposable-VM acknowledgment required");
            request_id = profile_probe::field(xml, L"RequestId");
            if (request_id.size() != 38 || request_id[0] != L'{' || request_id[37] != L'}' ||
                std::wstring_view(request_id).find_first_not_of(L"{}-0123456789abcdefABCDEF") != std::wstring_view::npos)
                throw hresult_invalid_argument(L"Invalid request identifier");
            auto config = profile_probe::parse(request);
            const auto family = Package::Current().Id().FamilyName();
            const auto profile = profile_probe::make_profile(config, family);
            VpnManagementAgent agent;
            auto existing = co_await agent.GetProfilesAsync();
            for (auto const& item : existing)
                if (item.ProfileName() == profile.ProfileName())
                    throw hresult_invalid_argument(L"Profile already exists; no replacement or deletion is performed");
            const auto status = co_await agent.AddProfileFromObjectAsync(profile);
            if (status != VpnManagementErrorStatus::Ok)
                throw hresult_error(E_FAIL, L"AddProfileFromObjectAsync status=" + to_hstring(static_cast<int32_t>(status)));
            bool matched = false;
            auto stored = co_await agent.GetProfilesAsync();
            for (auto const& item : stored) {
                if (item.ProfileName() != profile.ProfileName()) continue;
                auto plugin = item.try_as<VpnPlugInProfile>();
                matched = plugin && profile_probe::policy_matches(plugin, config, family);
            }
            if (!matched) throw hresult_error(E_FAIL, L"Created profile readback differs; setup inconclusive, restore VM snapshot");
            result = L"CREATED_AND_VERIFIED " + profile.ProfileName() + L" source=" + config.source +
                L" mode=" + config.mode + L" namespace=" + config.dns_namespace +
                L" selected=" + config.selected_exe + L"\r\nVPN was not connected.";
        } catch (hresult_error const& e) {
            result = L"SETUP_ERROR " + to_hstring(static_cast<uint32_t>(e.code().value)) + L" " + e.message();
        } catch (...) { result = L"SETUP_ERROR unknown"; }
        try {
            const auto file = co_await ApplicationData::Current().LocalFolder().CreateFileAsync(
                L"profile-provision.txt", CreationCollisionOption::ReplaceExisting);
            co_await FileIO::WriteTextAsync(file, L"request=" + request_id + L"\r\n" + result);
        } catch (...) { OutputDebugStringW(L"VPN profile probe: could not save setup result\n"); }
        CoreApplication::Exit();
    }
};
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    init_apartment(apartment_type::multi_threaded);
    CoreApplication::Run(make<Provision>());
}
