#include "helpers.h"
#include <intsafe.h>
#include <LM.h>
#pragma comment(lib, "netapi32.lib")

HRESULT GetDomainName(_Outptr_result_nullonfailure_ PWSTR* ppszDomain)
{
    PWSTR pszName;
    DWORD cnddSize = 0;
    HRESULT hr = E_UNEXPECTED;
    *ppszDomain = nullptr;
    GetComputerNameEx(ComputerNameDnsDomain, nullptr, &cnddSize);
    if (cnddSize > 1)
    {
        hr = S_OK;
        pszName = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (cnddSize + 1)));
        if (pszName == nullptr)
        {
            hr = E_OUTOFMEMORY;
        }
        if (SUCCEEDED(hr) && !GetComputerNameEx(ComputerNameDnsDomain, pszName, &cnddSize))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
        if (SUCCEEDED(hr))
        {
            *ppszDomain = pszName;
        }
        if (FAILED(hr))
        {
            CoTaskMemFree(pszName);
        }
    }
    return hr;
}

BOOLEAN IsDomainJoined()
{
    LPWSTR name = nullptr;
    NETSETUP_JOIN_STATUS joinStatus;
    if (NetGetJoinInformation(NULL, &name, &joinStatus) == NERR_Success)
    {
        if (name)
        {
            NetApiBufferFree(name);
        }
        if (joinStatus == NetSetupDomainName) {
            return true;
        }
    }
    return false;
}

HRESULT CreateAuthDataRequest(_In_ PWSTR pszUsername, _In_ PWSTR pszPassword, _Outptr_result_nullonfailure_ LPVOID* data, _Outptr_ DWORD* size)
{
    u_short sizeUsername = (u_short)wcslen(pszUsername) * sizeof(wchar_t);
    u_short sizePassword = (u_short)wcslen(pszPassword) * sizeof(wchar_t);
    u_short sizeData = sizeUsername + sizePassword + sizeof(WORD) * 2;
    *data = static_cast<char*>(CoTaskMemAlloc(sizeData));
    if (!*data)
    {
        return E_OUTOFMEMORY;
    }
    char *p = (char *)*data;
    *((u_short*)p) = htons(sizeUsername);
    p += sizeof(u_short);
    if (memcpy_s(p, sizeUsername, pszUsername, sizeUsername) != 0)
    {
        goto error;
    }
    p += sizeUsername;
    *((u_short*)p) = htons(sizePassword);
    p += sizeof(u_short);
    if (memcpy_s(p, sizePassword, pszPassword, sizePassword) != 0)
    {
        goto error;
    }
    *size = sizeData;
    return S_OK;

error:
    CoTaskMemFree(*data);
    *data = nullptr;
    return E_UNEXPECTED;
}

HRESULT AddDomainUnesp(_Inout_ PWSTR *pszUserName)
{
    HRESULT hr = S_OK;
    const wchar_t* pchWhack = wcschr(*pszUserName, L'@');
    const wchar_t* pchEnd = (*pszUserName) + wcslen(*pszUserName) - 1;
    static PCWSTR szUnespDomain = L"@unesp.br";
    static const size_t lenUnespDomain = wcslen(szUnespDomain);
    size_t lenUsername = wcslen(*pszUserName);

    if (pchWhack != nullptr)
    {
        const wchar_t* pchDomainBegin = pchWhack;
        if (wcscmp(szUnespDomain, pchDomainBegin) == 0)
        {
            return S_FALSE;
        }
        size_t lenUsername = pchWhack - (*pszUserName) - 1;
    }
    PWSTR pszNewUsername = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenUsername + lenUnespDomain + 1)));
    if (pszNewUsername == NULL)
    {
        hr = E_OUTOFMEMORY;
    }
    if (SUCCEEDED(hr))
    {
        hr = StringCchCopyN(pszNewUsername, lenUsername + lenUnespDomain + 1, *pszUserName, lenUsername);
    }
    if (SUCCEEDED(hr))
    {
        hr = StringCchCat(pszNewUsername, lenUsername + lenUnespDomain + 1, szUnespDomain);
    }
    if (FAILED(hr))
    {
        CoTaskMemFree(pszNewUsername);
    }
    else
    {
        CoTaskMemFree(*pszUserName);
        *pszUserName = pszNewUsername;
    }
    return hr;
}

BOOL IsDownLevelLogonName(PCWSTR pszUserName)
{
    const wchar_t* pchWhack = wcschr(pszUserName, L'\\');
    return pchWhack != NULL;
}
