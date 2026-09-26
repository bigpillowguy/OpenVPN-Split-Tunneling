#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shobjidl.h>
#include <iostream>
#include "ProfileConfig.h"

// VM-only explicit packaged activation; never called by build/offline tests.
int wmain(int argc, wchar_t** argv) {
    if (argc != 8 || wcscmp(argv[1], L"--inside-disposable-vm") != 0) {
        std::wcerr << L"VM only: ProfileActivate --inside-disposable-vm PACKAGE_FAMILY runtime|profile all|selected .vpn-probe.test|. SELECTED_EXE TRANSPORT_IPV4\n";
        return 2;
    }
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    try {
        const std::wstring family(argv[2]);
        if (!family.starts_with(L"VpnPlatformResearch_") ||
            family.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != std::wstring::npos)
            throw winrt::hresult_invalid_argument(L"Expected this laboratory package family");
        profile_probe::Config config{argv[3], argv[4], argv[5], argv[6], argv[7]};
        auto request = profile_probe::serialize(config);
        winrt::Windows::Data::Xml::Dom::XmlDocument xml; xml.LoadXml(request);
        profile_probe::append(xml, L"VmAcknowledged", L"InsideDisposableVm");
        GUID request_id{}; winrt::check_hresult(CoCreateGuid(&request_id));
        wchar_t token[40]{}; StringFromGUID2(request_id, token, ARRAYSIZE(token));
        profile_probe::append(xml, L"RequestId", token);
        auto manager = winrt::create_instance<IApplicationActivationManager>(CLSID_ApplicationActivationManager);
        DWORD pid = 0;
        winrt::check_hresult(manager->ActivateApplication((family + L"!Provision").c_str(),
            xml.GetXml().c_str(), AO_NONE, &pid));
        std::wcout << L"Provisioning app activated, PID=" << pid << L" request=" << token << L". This is not profile-creation success.\n"
            << L"Require fresh LocalState\\profile-provision.txt CREATED_AND_VERIFIED before connecting "
            << profile_probe::profile_name(config).c_str() << L".\n";
    } catch (winrt::hresult_error const& e) {
        std::wcerr << L"SETUP_ERROR " << e.message().c_str() << L'\n'; return 1;
    }
}
