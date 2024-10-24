#include "helpers.h"
#include <windows.h>
#include <strsafe.h>
#include <new>
#include <netlistmgr.h>

#include "CUnespCredential.h"

class CUnespProvider : public ICredentialProvider,
                       public ICredentialProviderFilter
{
  public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CUnespProvider, ICredentialProvider), // IID_ICredentialProvider
            QITABENT(CUnespProvider, ICredentialProviderFilter), // IID_ICredentialProviderFilter
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

  public:
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(_In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const *pcpcs);

    IFACEMETHODIMP Advise(_In_ ICredentialProviderEvents *pcpe, _In_ UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(_Out_ DWORD *pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,  _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd);

    IFACEMETHODIMP GetCredentialCount(_Out_ DWORD *pdwCount,
                                      _Out_ DWORD *pdwDefault,
                                      _Out_ BOOL *pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
                                   _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc);

    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, _In_ GUID* rgclsidProviders, _Inout_ BOOL* rgbAllow, DWORD cProviders);

    IFACEMETHODIMP UpdateRemoteCredential(_In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn, _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut);

    friend HRESULT CUnespProvider_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv);

  protected:
    CUnespProvider();
    __override ~CUnespProvider();

  private:
    void _ReleaseEnumeratedCredentials();
    void _CreateEnumeratedCredentials(_Out_ DWORD* pdwCount, _Out_ DWORD* pdwDefault, _Out_ BOOL* pbAutoLogonWithDefault);
    HRESULT _EnumerateCredentials(_Out_ DWORD* pdwCount, _Out_ DWORD* pdwDefault, _Out_ BOOL* pbAutoLogonWithDefault);
private:
    long                                    _cRef;                  // Used for reference counting.
    CUnespCredential                        **_rgpCredentials;      // Credential
    ICredentialProvider* _pWrappedProvider;                         // Our wrapped provider.
    DWORD                                   _dwCredentialCount;
    DWORD                                   _dwWrappedDescriptorCount;  // The number of fields on each tile of our wrapped provider's 
                                                                        // credentials.
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
    ICredentialProviderUserArray            *_pCredProviderUserArray;
    DWORD                                   _dwFieldUsername;
    DWORD                                   _dwFieldPassword;
    DWORD                                   _dwFieldTileImage;
    INetworkListManager                     *_pNetworkListManager;
};
