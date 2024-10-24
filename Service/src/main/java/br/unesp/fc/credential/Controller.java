package br.unesp.fc.credential;

import jakarta.servlet.http.HttpServletRequest;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import javax.naming.NamingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class Controller {

    private final static Charset UTF_16LE = Charset.forName("UTF-16LE");

    private final CentralService centralService;
    private final AdService adService;
    private final UserService userService;

    public Controller(CentralService centralService, AdService adService, UserService userService) {
        this.centralService = centralService;
        this.adService = adService;
        this.userService = userService;
    }

    @PostMapping("/auth")
    public ResponseEntity login(HttpServletRequest request, @AuthenticationPrincipal UserDetails computer) throws IOException {
        var dis = new DataInputStream(request.getInputStream());
        var size = dis.readUnsignedShort();
        var buffer = new byte[size];
        dis.read(buffer);
        var username = new String(buffer, UTF_16LE);
        size = dis.readUnsignedShort();
        buffer = new byte[size];
        dis.read(buffer);
        var password = new String(buffer, UTF_16LE);
        String response = "";
        try {
            var token = centralService.login(username, password);
            var dn = adService.find(username);
            if (token.get() == null) {
                return new ResponseEntity(HttpStatus.UNAUTHORIZED);
            } else if (dn.get() == null) {
                var user = userService.createUser(username, token.get());
                adService.addUser(user, password);
                response = getUsername(user);
            } else if (dn.get() != null) {
                if (!adService.login(dn.get().getDn(), password).get()) {
                    adService.changePassword(dn.get().getDn(), password);
                }
                response = getUsername(dn.get());
            }
        } catch (Exception ex) {
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }
        log.info("Usuário autenticado: {} {}", computer.getUsername(), response);
        buffer = response.getBytes(UTF_16LE);
        return new ResponseEntity(buffer, HttpStatus.OK);
    }

    @GetMapping("/")
    public String home(@AuthenticationPrincipal LdapUserDetails user) {
        return "Hello!";
    }

    private String getUsername(DirContextOperations ctx) throws NamingException {
        String userPrincipalName = (String) ctx.getAttributes().get("userPrincipalName").get();
        if (userPrincipalName.endsWith("@unesp.br")) {
            return userPrincipalName;
        }
        return (String) ctx.getAttributes().get("sAMAccountName").get();
    }

}
