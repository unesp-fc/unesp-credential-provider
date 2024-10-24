# Unesp Credential Provider - Service

The Service is a Web Service that is responsible for verifying the user credentials and creating/updating the user in Active Directory.

Service uses another service to verify the user credentials via [OAuth 2.0 Password Grant](https://oauth.net/2/grant-types/password/). Internally, we call this service as Central. Service also uses other web services to identify the user category. These services are internal and are public avaliable. You need to modify this Service to suit your needs.

Service use [Spring Security Kerberos](https://spring.io/projects/spring-security-kerberos). Please refer to its documentation to setup Windows Active Directory and create a keytab file.
