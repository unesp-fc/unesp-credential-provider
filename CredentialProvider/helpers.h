#pragma once

#pragma warning(push)
#pragma warning(disable: 28251)
#include <credentialprovider.h>
#include <ntsecapi.h>
#pragma warning(pop)

#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>

#include <windows.h>
#include <strsafe.h>

#pragma warning(push)
#pragma warning(disable: 4995)
#include <shlwapi.h>
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable: 28301)
#include <wincred.h>
#pragma warning(pop)


HRESULT GetDomainName(_Outptr_result_nullonfailure_ PWSTR* ppszDomain);

BOOLEAN IsDomainJoined();

HRESULT CreateAuthDataRequest(_In_ PWSTR pszUsername, _In_ PWSTR pszPassword, _Outptr_result_nullonfailure_ LPVOID* data, _Outptr_ DWORD* size);

HRESULT AddDomainUnesp(_Inout_ PWSTR *pszUserName);

BOOL IsDownLevelLogonName(PCWSTR pszUserName);
