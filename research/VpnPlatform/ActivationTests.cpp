#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winrt/Windows.ApplicationModel.Background.h>
#include <winrt/Windows.Foundation.h>
#include <iostream>

// Verifies only the DLL's local COM factory. Never invokes IBackgroundTask.Run,
// creates a VPN profile/channel, registers a package, or opens a socket.
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    HMODULE module = LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!module) return 3;
    using Activate = HRESULT(__stdcall*)(void*, void**);
    const auto activate = reinterpret_cast<Activate>(GetProcAddress(module, "DllGetActivationFactory"));
    if (!activate) return 4;
    try {
        winrt::hstring name(L"VpnPlatform.ProbeTask");
        {
            winrt::Windows::Foundation::IActivationFactory factory{nullptr};
            winrt::check_hresult(activate(winrt::get_abi(name), winrt::put_abi(factory)));
            auto task = factory.ActivateInstance<winrt::Windows::ApplicationModel::Background::IBackgroundTask>();
            if (!task) return 5;
        }
        winrt::hstring unknown(L"VpnPlatform.Unknown"); void* value = reinterpret_cast<void*>(1);
        if (activate(winrt::get_abi(unknown), &value) != CLASS_E_CLASSNOTAVAILABLE || value != nullptr) return 6;
        std::cout << "Activation factory checks passed; background task Run was not called.\n";
    } catch (winrt::hresult_error const& e) {
        std::wcerr << L"Factory failure: " << e.message().c_str() << L'\n'; return 7;
    }
    FreeLibrary(module); return 0;
}
