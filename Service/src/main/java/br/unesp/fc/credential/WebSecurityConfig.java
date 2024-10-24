package br.unesp.fc.credential;

import java.nio.file.Paths;
import java.util.Hashtable;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.io.FileSystemResource;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.GlobalSunJaasKerberosConfig;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.client.config.SunJaasKrb5LoginConfig;
import org.springframework.security.kerberos.client.ldap.KerberosLdapContextSource;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Value("${app.ad-server}")
    private String adServer;

    @Value("${app.service-principal}")
    private String servicePrincipal;

    @Value("${app.keytab-location}")
    private String keytabLocation;

    @Value("${app.ldap-search-base}")
    private String ldapSearchBase;

    @Value("${app.ldap-search-filter}")
    private String ldapSearchFilter;

    private boolean debug;

    @Autowired
    public void setDebug(ConfigurableEnvironment env) {
        this.debug = isSet(env, "debug") || isSet(env, "trace");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider = kerberosServiceAuthenticationProvider();
        ProviderManager providerManager = new ProviderManager(kerberosServiceAuthenticationProvider);
        http
                .authorizeHttpRequests((authz) -> authz
                .anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                .authenticationEntryPoint(spnegoEntryPoint())
                )
                .logout((logout) -> logout
                .permitAll()
                )
                .authenticationProvider(kerberosServiceAuthenticationProvider)
                .addFilterBefore(spnegoAuthenticationProcessingFilter(providerManager),
                        BasicAuthenticationFilter.class)
                .csrf((csrf) -> csrf.disable());
        return http.build();
    }

    public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() throws Exception {
        KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setUserDetailsService(ldapUserDetailsService());
        return provider;
    }

    @Bean
    public SpnegoEntryPoint spnegoEntryPoint() {
        return new SpnegoEntryPoint();
    }

    public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
            AuthenticationManager authenticationManager) {
        SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal(servicePrincipal);
        ticketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
        ticketValidator.setDebug(debug);
        return ticketValidator;
    }

    @Bean
    public KerberosLdapContextSource kerberosLdapContextSource() throws Exception {
        KerberosLdapContextSource contextSource = new KerberosLdapContextSource(adServer);
        contextSource.setAuthenticationStrategy(new DirContextAuthenticationStrategy() {
            @Override
            public void setupEnvironment(Hashtable<String, Object> env, String userDn, String password) throws NamingException {
                env.put("javax.security.sasl.qop", "auth-conf");
            }

            @Override
            public DirContext processContextAfterCreation(DirContext ctx, String userDn, String password) throws NamingException {
                return ctx;
            }
        });
        contextSource.setLoginConfig(loginConfig());
        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.ldap.attributes.binary", "nTSecurityDescriptor");
        contextSource.setBaseEnvironmentProperties(env);
        return contextSource;
    }

    public SunJaasKrb5LoginConfig loginConfig() throws Exception {
        SunJaasKrb5LoginConfig loginConfig = new SunJaasKrb5LoginConfig();
        loginConfig.setKeyTabLocation(new FileSystemResource(keytabLocation));
        loginConfig.setServicePrincipal(servicePrincipal);
        loginConfig.setDebug(debug);
        loginConfig.setIsInitiator(true);
        loginConfig.afterPropertiesSet();
        return loginConfig;
    }

    @Bean
    public LdapUserDetailsService ldapUserDetailsService() throws Exception {
        FilterBasedLdapUserSearch userSearch
                = new FilterBasedLdapUserSearch(ldapSearchBase, ldapSearchFilter, kerberosLdapContextSource());
        LdapUserDetailsService service
                = new LdapUserDetailsService(userSearch);
        service.setUserDetailsMapper(new LdapUserDetailsMapper());
        return service;
    }

    @Bean
    public static GlobalSunJaasKerberosConfig globalSunJaasKerberosConfig(ConfigurableEnvironment env) {
        GlobalSunJaasKerberosConfig config = new GlobalSunJaasKerberosConfig();
        if (isSet(env, "debug") || isSet(env, "trace")) {
            config.setDebug(true);
        }
        String krbconfig = "krb5.ini";
        if (env.getProperty("app.krbconfig") != null) {
            krbconfig = env.getProperty("app.krbconfig");
        }
        config.setKrbConfLocation(Paths.get(krbconfig).toAbsolutePath().toString());
        return config;
    }

    private static boolean isSet(ConfigurableEnvironment environment, String property) {
        String value = environment.getProperty(property);
        return (value != null && !value.equals("false"));
    }

}
