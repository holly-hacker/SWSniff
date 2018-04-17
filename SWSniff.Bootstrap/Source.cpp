#include <Windows.h>
#include <metahost.h>
#include <string>
#include <array>
#pragma comment(lib, "mscoree.lib")

void inject(const std::wstring& path)
{
	// Build the runtime
	auto* meta_host = static_cast<ICLRMetaHost*>(nullptr);
	CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&meta_host));

	auto* runtime_info = static_cast<ICLRRuntimeInfo*>(nullptr);
	meta_host->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&runtime_info));

	auto* clr_runtime_host = static_cast<ICLRRuntimeHost*>(nullptr);
	runtime_info->GetInterface(CLSID_CLRRuntimeHost, IID_PPV_ARGS(&clr_runtime_host));

	// Start the runtime
	clr_runtime_host->Start();

	// Execute managed assembly
	auto return_value = static_cast<DWORD>(0);
	clr_runtime_host->ExecuteInDefaultAppDomain(
		path.c_str(),
		L"SWSniff.Internal.InjectStart",
		L"Main",
		L"",
		&return_value);

	clr_runtime_host->Stop();

	// Release runtime objects
	meta_host->Release();
	runtime_info->Release();
	clr_runtime_host->Release();
}

void on_attach(HINSTANCE instance)
{
	// Get path of the bootstrap dll
	auto bootstrap_path_cstr = std::array<wchar_t, MAX_PATH>();
	GetModuleFileNameW(instance, bootstrap_path_cstr.data(), MAX_PATH);

	auto bootstrap_path = std::wstring(bootstrap_path_cstr.begin(), bootstrap_path_cstr.end());

	// Remove file name from the path
	bootstrap_path.resize(bootstrap_path.find_last_of(L'\\'));

	// Inject the module
	inject(bootstrap_path + L"\\SWSniff.Internal.dll");

	// Unload the bootstrap
	FreeLibraryAndExitThread(instance, 0);
}

BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&on_attach), instance, 0, nullptr);
	}
	return TRUE;
}