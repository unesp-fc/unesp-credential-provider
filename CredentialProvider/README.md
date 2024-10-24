# Unesp Credential Provider - CredentialProvider

CredentialProvider is a [Windows Credential Provider](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows) that that checks user credentials with a custom Service before proceeding with normal Windows authentication. This CredentialProvider is a wrapper for PasswordCredentialProvider or OnexCredentialProvider (for machine that needs network logon before logging into AD) and will disable them when in use. This CredentialProvider is only activate when a machine is domain joined.

For consume the Service, CredentialProvider needs authenticate itself using SPNEGO/Kerberos. As a Credential Provider runs as Local System (LUID 0x3e7), it will use the machine account automatically.
