#include <unknwn.h>
#include "CUnespCredential.h"
#include "guid.h"

#pragma comment(lib, "Ws2_32.lib")

PCWSTR LOGIN_TEXT = L"Login em: ";

CUnespCredential::CUnespCredential():
    _cRef(1),
    _pWrappedCredential(nullptr),
    _pWrappedConnectableCredential(nullptr),
    _pCredProvCredentialEvents(nullptr),
    _pszUsername(nullptr),
    _pszComputerName(nullptr),
    _pwszFieldUsername(nullptr),
    _pwszFieldPassword(nullptr),
    _dwFieldUsername(-1),
    _dwFieldPassword(-1),
    _dwFieldTileImage(-1)
{
    DllAddRef();

    _hSession = WinHttpOpen(L"UnespCredentialProvider",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    WinHttpSetTimeouts(_hSession, 15 * 1000, 15 * 1000, 30 * 1000, 30 * 1000);
    DWORD dwSecureOption = 0x00000A00;
    WinHttpSetOption(_hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &dwSecureOption, sizeof(DWORD));
}

CUnespCredential::~CUnespCredential()
{
    CoTaskMemFree(_pszUsername);
    CoTaskMemFree(_pszComputerName);
    CoTaskMemFree(_pwszFieldUsername);
    CoTaskMemFree(_pwszFieldPassword);
    if (_pWrappedCredential != nullptr)
    {
        _pWrappedCredential->Release();
    }
    if (_pNetworkListManager != nullptr)
    {
        _pNetworkListManager->Release();
    }
    DllRelease();
}

HRESULT CUnespCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                     _In_ ICredentialProviderCredential* pWrappedCredential,
                                     _In_ INetworkListManager* pNetworkListManager,
                                     DWORD dwFieldUsername,
                                     DWORD dwFieldPassword,
                                     DWORD dwFieldTileImage)
{
    HRESULT hr = S_OK;
    _cpus = cpus;
    _dwFieldUsername = dwFieldUsername;
    _dwFieldPassword = dwFieldPassword;
    _dwFieldTileImage = dwFieldTileImage;
    if (_pWrappedCredential != nullptr) {
        _pWrappedCredential->Release();
    }
    _pWrappedCredential = pWrappedCredential;
    _pWrappedCredential->AddRef();
    if (_pNetworkListManager != nullptr)
    {
        _pNetworkListManager->Release();
    }
    _pNetworkListManager = pNetworkListManager;
    _pNetworkListManager->AddRef();
    pWrappedCredential->QueryInterface(IID_PPV_ARGS(&(_pWrappedConnectableCredential)));
    return hr;
}

HRESULT CUnespCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    HRESULT hr = _pWrappedCredential->Advise(pcpce);
    if (FAILED(hr))
    {
        return hr;
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&(_pCredProvCredentialEvents)));
}

HRESULT CUnespCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    _pWrappedCredential->UnAdvise();
    return S_OK;
}

HRESULT CUnespCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->SetSelected(pbAutoLogon);
}

HRESULT CUnespCredential::SetDeselected()
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->SetDeselected();
}

HRESULT CUnespCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    HRESULT hr = _pWrappedCredential->GetFieldState(dwFieldID, pcpfs, pcpfis);
    return hr;
}

HRESULT CUnespCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->GetStringValue(dwFieldID, ppwsz);
}

HRESULT CUnespCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential == nullptr)
    {
        return hr;
    }
    if (dwFieldID == _dwFieldTileImage)
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
        return hr;
    }
    return _pWrappedCredential->GetBitmapValue(dwFieldID, phbmp);
}

HRESULT CUnespCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->GetSubmitButtonValue(dwFieldID, pdwAdjacentTo);
}

HRESULT CUnespCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    hr = _pWrappedCredential->SetStringValue(dwFieldID, pwz);
    if (SUCCEEDED(hr))
    {
        if (dwFieldID == _dwFieldUsername)
        {
            CoTaskMemFree(_pwszFieldUsername);
            hr = SHStrDupW(pwz, &_pwszFieldUsername);
        }
        else if (dwFieldID == _dwFieldPassword)
        {
            CoTaskMemFree(_pwszFieldPassword);
            hr = SHStrDupW(pwz, &_pwszFieldPassword);
        }
    }
    return hr;
}

HRESULT CUnespCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->GetCheckboxValue(dwFieldID, pbChecked, ppwszLabel);
}

HRESULT CUnespCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->SetCheckboxValue(dwFieldID, bChecked);
}

HRESULT CUnespCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->GetComboBoxValueCount(dwFieldID, pcItems, pdwSelectedItem);
}

HRESULT CUnespCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->GetComboBoxValueAt(dwFieldID, dwItem, ppwszItem);
}

HRESULT CUnespCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->SetComboBoxSelectedValue(dwFieldID, dwSelectedItem);
}

HRESULT CUnespCredential::CommandLinkClicked(DWORD dwFieldID)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->CommandLinkClicked(dwFieldID);
}

HRESULT CUnespCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    if (_bConnectError || (_dwStatusCode > 0 && _dwStatusCode != 200 && _dwStatusCode != 401))
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        SHStrDupW(ERROR_SERVER_CONNECTION, ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_FALSE;
    }
    if (_dwStatusCode == 401)
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        _pWrappedCredential->ReportResult(STATUS_LOGON_FAILURE, 0, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
        return S_FALSE;
    }
    return _pWrappedCredential->GetSerialization(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
}

HRESULT CUnespCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    return _pWrappedCredential->ReportResult(ntsStatus, ntsSubstatus, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
}

HRESULT CUnespCredential::Connect(IQueryContinueWithStatus* pqcws)
{
    VARIANT_BOOL bIsConnected;
    BOOL bIsDownLevelLogonName = true;
    _bConnectError = false;
    _dwStatusCode = 0;
    if (_pWrappedCredential == nullptr)
    {
        return E_UNEXPECTED;
    }
    HRESULT hr = S_OK;
    if (_pwszFieldUsername != nullptr)
    {
        bIsDownLevelLogonName = IsDownLevelLogonName(_pwszFieldUsername);
        if (!bIsDownLevelLogonName)
        {

            hr = AddDomainUnesp(&_pwszFieldUsername);
            if (FAILED(hr))
            {
                return hr;
            }
            if (hr == S_OK)
            {
                hr = _pWrappedCredential->SetStringValue(_dwFieldUsername, _pwszFieldUsername);
            }
            if (FAILED(hr))
            {
                return hr;
            }
        }
    }
    if (_pWrappedConnectableCredential != nullptr)
    {
        hr = _pWrappedConnectableCredential->Connect(pqcws);
        if (FAILED(hr) && hr != E_FAIL)
        {
            return hr;
        }
    }
    if (_pNetworkListManager != nullptr)
    {
        hr = _pNetworkListManager->get_IsConnected(&bIsConnected);
        if (!bIsConnected)
        {
            return E_FAIL;
        }
    }
    if (_pwszFieldUsername != nullptr && _pwszFieldPassword != nullptr)
    {
        if (_cpus == CPUS_LOGON && !bIsDownLevelLogonName)
        {
            hr = _Auth(pqcws);
            if (SUCCEEDED(hr))
            {
                _pWrappedCredential->SetStringValue(_dwFieldUsername, _pszUsername);
            }
        }
    }
    if (_pWrappedConnectableCredential != nullptr)
    {
        return hr;
    }
    return E_FAIL;
}

HRESULT CUnespCredential::Disconnect()
{
    if (_pWrappedConnectableCredential != nullptr)
    {
        return _pWrappedConnectableCredential->Disconnect();
    }
    return E_NOTIMPL;
}

HRESULT CUnespCredential::_Auth(IQueryContinueWithStatus* pqcws)
{
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL bResults = FALSE;
    HRESULT hr = S_FALSE;
    PWSTR pszDomainName = NULL;
    PWSTR pszNewUsername = NULL;
    LPVOID data = NULL;
    DWORD sizeData;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    DWORD d = 0;
    _bConnectError = true;

    hr = GetDomainName(&pszDomainName);
    if (FAILED(hr))
    {
        goto end;
    }

    hConnect = WinHttpConnect(_hSession, pszDomainName, DOMIAN_WEBSERVICE_PORT, 0);
    if (!hConnect)
    {
        goto end;
    }
    hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/auth", NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest)
    {
        goto end;
    }
    d = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
    bResults = WinHttpSetOption(hRequest, WINHTTP_OPTION_AUTOLOGON_POLICY, &d, sizeof(d));
    WinHttpSetCredentials(hRequest, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_NEGOTIATE,
        NULL, NULL, NULL);

    hr = CreateAuthDataRequest(_pwszFieldUsername, _pwszFieldPassword, &data, &sizeData);
    if (FAILED(hr))
    {
        goto end;
    }
    hr = E_UNEXPECTED;
    bResults = WinHttpSendRequest(hRequest, NULL, 0, data, sizeData, sizeData, 0);
    if (!bResults)
    {
        goto end;
    }
    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults)
    {
        goto end;
    }
    dwSize = sizeof(_dwStatusCode);
    bResults = WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &_dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    if (!bResults)
    {
        goto end;
    }
    if (_dwStatusCode != HTTP_STATUS_OK)
    {
        // Authentication failure
        CoTaskMemFree(_pszUsername);
        _pszUsername = nullptr;
        _bConnectError = false;
        goto end;
    }
    bResults = WinHttpQueryDataAvailable(hRequest, &dwSize);
    if (!bResults)
    {
        goto end;
    }
    _pszUsername = static_cast<PWSTR>(CoTaskMemRealloc(_pszUsername, dwSize + sizeof(WCHAR)));
    if (!_pszUsername)
    {
        hr = E_OUTOFMEMORY;
        goto end;
    }
    ZeroMemory(_pszUsername, dwSize + sizeof(WCHAR));
    // Read actual username
    bResults = WinHttpReadData(hRequest, _pszUsername,
        dwSize, &dwDownloaded);
    if (bResults)
    {
        _bConnectError = false;
        hr = S_OK;
    }

end:
    CoTaskMemFree(pszDomainName);
    if (hRequest)
    {
        WinHttpCloseHandle(hRequest);
    }
    if (hConnect)
    {
        WinHttpCloseHandle(hConnect);
    }
    if (data)
    {
        SecureZeroMemory(data, sizeData);
        CoTaskMemFree(data);
    }
    return hr;
}
