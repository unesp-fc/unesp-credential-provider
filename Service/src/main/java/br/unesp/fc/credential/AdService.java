package br.unesp.fc.credential;

import br.unesp.fc.credential.sddl.SDDLUtils;
import java.nio.charset.Charset;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.concurrent.CompletableFuture;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import lombok.extern.slf4j.Slf4j;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.controls.SDFlagsControl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.ldap.core.ContextExecutor;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AdService {

    @Value("${app.ldap-search-base}")
    private String ldapSearchBase;

    @Value("${app.ad-domain}")
    private String domain;

    final static String CON_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    final static Charset UNICODE =  Charset.forName("UTF-16LE");

    private final LdapContext ldapContext;
    private final ContextSource contextSource;
    private final SearchControls searchControls = new SearchControls();

    private final SpringSecurityLdapTemplate template;

    public AdService(ContextSource contextSource, @Value("${app.ad-server}") String adServer) throws NamingException {
        this.contextSource = contextSource;
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, CON_FACTORY);
        env.put(Context.PROVIDER_URL, adServer);
        ldapContext = new InitialLdapContext(env, null);
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        template = new SpringSecurityLdapTemplate(this.contextSource);
    }

    @Async
    public CompletableFuture<Boolean> login(Name user, String password) {
        log.debug("Login: {}", user);
        LdapContext userContext = null;
        try {
            userContext = ldapContext.newInstance(null);
            userContext.addToEnvironment(InitialDirContext.SECURITY_PRINCIPAL, user.toString());
            userContext.addToEnvironment(InitialDirContext.SECURITY_CREDENTIALS, password);
            userContext.reconnect(null);
            return CompletableFuture.completedFuture(true);
        } catch (NamingException ex) {
            return CompletableFuture.completedFuture(false);
        } finally {
            LdapUtils.closeContext(userContext);
        }
    }

    @Async
    public CompletableFuture<DirContextOperations> find(String user) {
        if (user.contains("\\")) {
            user = user.split("\\\\", 2)[0];
        }
        if (user.contains("@")) {
            user = user.split("@", 2)[0];
        }
        log.debug("Find: {}", user);
        try {
            DirContextOperations operations = template.searchForSingleEntry(ldapSearchBase,
                    "(& (| (userPrincipalName={0}@*) (sAMAccountName={0}) ) (sAMAccountType=805306368) )",
                        new String[] { user });
            log.debug("Found: {} {}", user, operations.getDn());
            return CompletableFuture.completedFuture(operations);
        } catch (IncorrectResultSizeDataAccessException ex) {
            log.debug("Not found: {}", user);
            return CompletableFuture.completedFuture(null);
        }
    }

    private static byte[] getUnicodePassword(String password) {
        return ("\"" + password + "\"").getBytes(UNICODE);
    }

    public void changePassword(Name dn, String password) {
        ModificationItem modPassword = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                new BasicAttribute("unicodePwd", getUnicodePassword(password)));
        template.modifyAttributes(dn, new ModificationItem[]{modPassword});
    }

    public void addUser(DirContextOperations context, String password) {
        verifyOrganizationUnit((LdapName) context.getDn());
        log.info("Add user {}", context.getDn());
        // NORMAL_ACCOUNT(0x200) + DONT_EXPIRE_PASSWD(0x10000)
        context.addAttributeValue("userAccountControl", "66048");
        context.addAttributeValue("unicodePwd", getUnicodePassword(password));
        template.bind(context);
        setUserCannotChangePassword((LdapName) context.getDn());
    }

    public void verifyOrganizationUnit(LdapName dn) {
        log.debug("Verifing OU: {}", dn);
        for (int i = 0; i < dn.size(); i++) {
            var prefix = (LdapName) dn.getPrefix(i + 1);
            if (prefix.getRdn(i).getType().equalsIgnoreCase("OU")) {
                if (!exists(prefix)) {
                    createOrganizationalUnit(prefix);
                }
            }
        }
    }

    public static long toWindowsSytemTime(LocalDateTime time) {
        return (Timestamp.valueOf(time).getTime() + 11644473600000l) * 10000;
    }

    public static String getDomain(LdapName name) {
        ArrayList<String> dcs = new ArrayList<>(name.getRdns().size());
        for (var rdn : name.getRdns().reversed()) {
            if (rdn.getType().equals("dc")) {
                dcs.add(rdn.getValue().toString());
            }
        }
        return String.join(".", dcs);
    }

    public boolean exists(LdapName dn) {
        try {
            template.lookup(dn);
            return true;
        } catch (NameNotFoundException ex) {
            return false;
        }
    }

    public void createOrganizationalUnit(LdapName dn) {
        log.info("Creating OU: {}", dn);
        DirContextAdapter context = new DirContextAdapter(dn);
        context.setAttributeValues("objectclass", new String[] { "top", "organizationalUnit" });
        context.setAttributeValue("ou", dn.getRdn(dn.size() - 1).getValue());
        template.bind(context);
    }

    public void setUserCannotChangePassword(LdapName dn) {
        try {
            var attributes = (Attributes) template.executeReadOnly((ContextExecutor) (ctx) -> {
                ((LdapContext)ctx).setRequestControls(new Control[] { new SDFlagsControl(0x4) });
                return ctx.getAttributes(dn);
            });
            byte[] orig = (byte[]) attributes.get("nTSecurityDescriptor").get();
            SDDL sddl = new SDDL(orig);
            SDDLUtils.setUserCannotChangePassword(sddl, true);
            ModificationItem modPassword = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                    new BasicAttribute("nTSecurityDescriptor", SDDLUtils.SDDLtoByteArray(sddl)));
            template.modifyAttributes(dn, new ModificationItem[]{modPassword});
        } catch (Exception ex) {
            log.error("setUserCannotChangePassword({})", dn, ex);
        }
    }

}
