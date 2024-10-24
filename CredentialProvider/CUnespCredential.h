#pragma once

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <propkey.h>
#include <Shlwapi.h>
#include <WinHttp.h>
#include <netlistmgr.h>
#include "common.h"
#include "dll.h"
#include "resource.h"

#pragma comment(lib, "winhttp.lib")

#define DOMIAN_WEBSERVICE_PORT 8443

class CUnespCredential : public IConnectableCredentialProviderCredential
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
            QITABENT(CUnespCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
            QITABENT(CUnespCredential, IConnectableCredentialProviderCredential), //IID_IConnectableCredentialProviderCredential
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }
  public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(_In_ ICredentialProviderCredentialEvents *pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(_Out_ BOOL *pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                 _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                    _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus,
                                NTSTATUS ntsSubstatus,
                                _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);

    // IConnectableCredentialProviderCredential
    IFACEMETHODIMP Connect(IQueryContinueWithStatus* pqcws);
    IFACEMETHODIMP Disconnect();

  public:
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       _In_ ICredentialProviderCredential *pWrappedCredential,
                       _In_ INetworkListManager *pNetworkListManager,
                       DWORD dwFieldUsername,
                       DWORD dwFieldPassword,
                       DWORD dwFieldTileImag);
    CUnespCredential();

  private:

    virtual ~CUnespCredential();
    HRESULT _Auth(IQueryContinueWithStatus* pqcws);
    long                                    _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;                                          // The usage scenario for which we were enumerated.
    PWSTR                                   _pszUsername;
    ICredentialProviderCredentialEvents2*   _pCredProvCredentialEvents;                     // Used to update fields.
    ICredentialProviderCredential*          _pWrappedCredential;                            // Our wrapped credential.
    IConnectableCredentialProviderCredential*       _pWrappedConnectableCredential;         // Our wrapped credential (Connectable).
                                                                                            // CredentialEvents2 for Begin and EndFieldUpdates.
    HINTERNET                               _hSession;
    bool                                    _bConnectError;
    PWSTR                                   _pszComputerName;
    DWORD                                   _dwFieldUsername;
    DWORD                                   _dwFieldPassword;
    DWORD                                   _dwFieldTileImage;
    PWSTR                                   _pwszFieldUsername;                            // Store Username
    PWSTR                                   _pwszFieldPassword;                            // Store Password
    DWORD                                   _dwStatusCode;                                 // Status code from WebService
    INetworkListManager*                    _pNetworkListManager;
};
