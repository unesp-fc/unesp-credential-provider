package br.unesp.fc.credential;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

public class LdapUserDetailsService extends org.springframework.security.ldap.userdetails.LdapUserDetailsService {

    private final Log logger = LogFactory.getLog(getClass());

    public LdapUserDetailsService(LdapUserSearch userSearch) {
        super(userSearch);
    }

    public LdapUserDetailsService(LdapUserSearch userSearch, LdapAuthoritiesPopulator authoritiesPopulator) {
        super(userSearch, authoritiesPopulator);
    }

    @Override
    public UserDetails loadUserByUsername(String upn) throws UsernameNotFoundException {
        String username = upn.split("@", 2)[0];
        try {
            return super.loadUserByUsername(username);
        } catch (UsernameNotFoundException ex) {
            logger.warn("Invalid user: " + upn);
            throw new UsernameNotFoundException(upn);
        }
    }

}
