# Unesp Credential Provider

This is a Windows Credential Provider designed to syncrhonize user accounts with Active Directory.

The project consists of two parts:

* [Service](Service/README.md): The Web Service that runs on the Windows Server.
* [CredentialProvider](CredentialProvider/README.md): The Credential Provider itself.

## How it works

Credential Provider wraps the existing credential and implements [IConnectableCredentialProvider](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nn-credentialprovider-iconnectablecredentialprovidercredential). On the IConnectableCredentialProvider::Connect method, it connects to the Service to verify the username and password. If the uthentication fails, Credential Provider stops the login process.

The Service checks the username and password received from the provider on our database. If they are corret, the Service verifies if the user exists in Active Directory and if the password matches. If not, it will create the user or update the password.

After that, the Windows will authenticate succefully on Active Directory.

The provider authenticates itself to the Service using the machine account via SPNEGO/kerberos.
