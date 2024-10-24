#include <initguid.h>
#include "CUnespProvider.h"
#include "CUnespCredential.h"
#include "guid.h"

CUnespProvider::CUnespProvider():
    _cRef(1),
    _rgpCredentials(nullptr),
    _pWrappedProvider(nullptr),
    _pCredProviderUserArray(nullptr),
    _pNetworkListManager(nullptr),
    _dwFieldUsername(-1),
    _dwFieldPassword(-1),
    _dwFieldTileImage(-1)
{
    DllAddRef();
    _dwCredentialCount = 0;
    _dwWrappedDescriptorCount = 0;
}

CUnespProvider::~CUnespProvider()
{
    _ReleaseEnumeratedCredentials();
    if (_pNetworkListManager != nullptr)
    {
        _pNetworkListManager->Release();
    }
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }
    if (_pWrappedProvider != nullptr)
    {
        _pWrappedProvider->Release();
    }

    DllRelease();
}

HRESULT CUnespProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags)
{
    HRESULT hr;
    IUnknown* pUnknown = NULL;

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _cpus = cpus;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }
    if (FAILED(hr))
    {
        return hr;
    }
    hr = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, IID_PPV_ARGS(&_pNetworkListManager));
    if (FAILED(hr))
    {
        return hr;
    }

    // Try Onex first in case we need to connect on Wlan
    hr = ::CoCreateInstance(CLSID_OnexCredentialProvider, NULL, CLSCTX_ALL, IID_PPV_ARGS(&pUnknown));
    if (SUCCEEDED(hr))
    {
        hr = pUnknown->QueryInterface(IID_PPV_ARGS(&(_pWrappedProvider)));
        if (SUCCEEDED(hr))
        {
            hr = _pWrappedProvider->SetUsageScenario(cpus, dwFlags);
            if (SUCCEEDED(hr))
            {
                return hr;
            }
        }
    }
    if (FAILED(hr))
    {
        if (_pWrappedProvider != NULL)
        {
            _pWrappedProvider->Release();
            _pWrappedProvider = NULL;
        }
    }

    hr = ::CoCreateInstance(CLSID_V1PasswordCredentialProvider, NULL, CLSCTX_ALL, IID_PPV_ARGS(&pUnknown));
    if (SUCCEEDED(hr))
    {
        hr = pUnknown->QueryInterface(IID_PPV_ARGS(&(_pWrappedProvider)));
        if (SUCCEEDED(hr))
        {
            hr = _pWrappedProvider->SetUsageScenario(cpus, dwFlags);
        }
    }
    if (FAILED(hr))
    {
        if (_pWrappedProvider != NULL)
        {
            _pWrappedProvider->Release();
            _pWrappedProvider = NULL;
        }
    }

    return hr;
}

HRESULT CUnespProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const* pcpcs)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->SetSerialization(pcpcs);
    }

    return hr;
}

HRESULT CUnespProvider::Advise(
    _In_ ICredentialProviderEvents* pcpe,
    _In_ UINT_PTR upAdviseContext)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->Advise(pcpe, upAdviseContext);
    }
    return hr;
}

HRESULT CUnespProvider::UnAdvise()
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->UnAdvise();
    }
    return hr;
}

HRESULT CUnespProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->GetFieldDescriptorCount(&(_dwWrappedDescriptorCount));
        if (SUCCEEDED(hr))
        {
            *pdwCount = _dwWrappedDescriptorCount;
        }
    }

    return hr;
}

HRESULT CUnespProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedProvider != NULL)
    {
        if (ppcpfd != NULL)
        {
            if (dwIndex < _dwWrappedDescriptorCount)
            {
                hr = _pWrappedProvider->GetFieldDescriptorAt(dwIndex, ppcpfd);
                if (SUCCEEDED(hr))
                {
                    if ((*ppcpfd)->cpft == CPFT_EDIT_TEXT
                        && IsEqualGUID((*ppcpfd)->guidFieldType, CPFG_LOGON_USERNAME))
                    {
                        _dwFieldUsername = (*ppcpfd)->dwFieldID;
                        CoTaskMemFree((*ppcpfd)->pszLabel);
                        hr = SHStrDupW(FIELD_USERNAME_LABEL, &((*ppcpfd)->pszLabel));
                        if (FAILED(hr))
                        {
                            CoTaskMemFree(*ppcpfd);
                            *ppcpfd = nullptr;
                        }
                    }
                    else if ((*ppcpfd)->cpft == CPFT_PASSWORD_TEXT
                        && IsEqualGUID((*ppcpfd)->guidFieldType, CPFG_LOGON_PASSWORD))
                    {
                        _dwFieldPassword = (*ppcpfd)->dwFieldID;
                    }
                    else if ((*ppcpfd)->cpft == CPFT_TILE_IMAGE
                        && _dwFieldTileImage > (*ppcpfd)->dwFieldID)
                    {
                        _dwFieldTileImage = (*ppcpfd)->dwFieldID;
                    }
                }
            }
            else
            {
                hr = E_INVALIDARG;
            }
        }
        else
        {
            hr = E_INVALIDARG;
        }
    }

    return hr;
}

HRESULT CUnespProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    _ReleaseEnumeratedCredentials();
    _CreateEnumeratedCredentials(pdwCount, pdwDefault, pbAutoLogonWithDefault);

    *pdwCount = _dwCredentialCount;

    return S_OK;
}

HRESULT CUnespProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

    if ((dwIndex < _dwCredentialCount) &&
        (ppcpc != nullptr) &&
        (_rgpCredentials != nullptr) &&
        (_rgpCredentials[dwIndex] != nullptr))
    {
        hr = _rgpCredentials[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
}

void CUnespProvider::_CreateEnumeratedCredentials(
    _Out_ DWORD* pdwCount,
    _Out_ DWORD* pdwDefault,
    _Out_ BOOL* pbAutoLogonWithDefault)
{
    switch (_cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _EnumerateCredentials(pdwCount, pdwDefault, pbAutoLogonWithDefault);
        break;
    default:
        break;
    }
}

void CUnespProvider::_ReleaseEnumeratedCredentials()
{
    if (_rgpCredentials != nullptr)
    {
        for (DWORD i = 0; i < _dwCredentialCount; i++)
        {
            if (_rgpCredentials[i] != nullptr)
            {
                _rgpCredentials[i]->Release();
                _rgpCredentials[i] = nullptr;
            }
        }
        delete[] _rgpCredentials;
        _rgpCredentials = nullptr;
    }
}

HRESULT CUnespProvider::_EnumerateCredentials(_Out_ DWORD* pdwCount,
    _Out_ DWORD* pdwDefault,
    _Out_ BOOL* pbAutoLogonWithDefault)
{
    HRESULT hr = E_UNEXPECTED;
    DWORD dwDefault = 0;
    BOOL bAutoLogonWithDefault = FALSE;
    if (_pWrappedProvider == NULL)
    {
        return hr;
    }

    DWORD count;
    // Discover fields (_dwFieldUsername and _dwFieldPassword)
    hr = GetFieldDescriptorCount(&(count));
    if (FAILED(hr))
    {
        return hr;
    }
    for (DWORD lcv = 0; SUCCEEDED(hr) && lcv < count; lcv++)
    {
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR *pcpfd;
        hr = GetFieldDescriptorAt(lcv, &pcpfd);
        if (SUCCEEDED(hr))
        {
            CoTaskMemFree(pcpfd);
        }
    }

    hr = _pWrappedProvider->GetCredentialCount(&(_dwCredentialCount), &(dwDefault), &(bAutoLogonWithDefault));
    if (FAILED(hr))
    {
        return hr;
    }
    _rgpCredentials = new CUnespCredential * [_dwCredentialCount];
    if (_rgpCredentials == NULL)
    {
        return E_OUTOFMEMORY;
    }
    for (DWORD lcv = 0; SUCCEEDED(hr) && (lcv < _dwCredentialCount); lcv++)
    {
        _rgpCredentials[lcv] = new CUnespCredential();
        if (_rgpCredentials[lcv] != NULL)
        {
            ICredentialProviderCredential* pCredential;
            hr = _pWrappedProvider->GetCredentialAt(lcv, &(pCredential));
            if (SUCCEEDED(hr))
            {
                hr = _rgpCredentials[lcv]->Initialize(_cpus, pCredential, _pNetworkListManager, _dwFieldUsername, _dwFieldPassword, _dwFieldTileImage);
                if (FAILED(hr))
                {
                    // If initialization failed, clean everything up.
                    for (lcv = 0; lcv < _dwCredentialCount; lcv++)
                    {
                        if (_rgpCredentials[lcv] != NULL)
                        {
                            // Release the pointer to account for the local reference.
                            _rgpCredentials[lcv]->Release();
                            _rgpCredentials[lcv] = NULL;
                        }
                    }
                }
                pCredential->Release();
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    if (FAILED(hr))
    {
        if (_rgpCredentials != NULL)
        {
            delete _rgpCredentials;
            _rgpCredentials = NULL;
        }
    }
    else
    {
        *pdwCount = _dwCredentialCount;
        *pdwDefault = dwDefault;
        *pbAutoLogonWithDefault = bAutoLogonWithDefault;
    }

    return hr;
}

HRESULT CUnespProvider::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, _In_ GUID* rgclsidProviders, _Inout_ BOOL* rgbAllow, DWORD cProviders)
{
    if (cpus != CPUS_LOGON &&
        cpus != CPUS_UNLOCK_WORKSTATION)
    {
        return S_OK;
    }
    // This provider is intended to work only domain-joined
    if (!IsDomainJoined())
    {
        return S_OK;
    }
    for (DWORD i = 0; i < cProviders; i++) {
        if (IsEqualGUID(rgclsidProviders[i], CLSID_PasswordCredentialProvider))
        {
            rgbAllow[i] = false;
        }
        if (IsEqualGUID(rgclsidProviders[i], CLSID_OnexCredentialProvider))
        {
            rgbAllow[i] = false;
        }
    }
    return S_OK;
}

HRESULT CUnespProvider::UpdateRemoteCredential(_In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn, _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut)
{
    return E_NOTIMPL;
}

HRESULT CUnespProvider_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    CUnespProvider *pProvider = new(std::nothrow) CUnespProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}
