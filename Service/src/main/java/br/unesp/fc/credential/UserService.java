package br.unesp.fc.credential;

import br.unesp.fc.credential.vo.AlunoGraduacaoVO;
import br.unesp.fc.credential.vo.AlunoStrictoSensuVO;
import br.unesp.fc.credential.vo.ServidorPublicoVO;
import br.unesp.fc.credential.vo.TokenVO;
import br.unesp.fc.credential.vo.UsuarioVO;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import javax.naming.ldap.LdapName;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UserService {

    private final UnespService unespService;
    private final CentralService centralService;

    private final String domain;
    private final LdapName ldapBaseName;

    public UserService(UnespService unespService, CentralService centralService, @Value("${app.ad-domain}") String domain) {
        this.unespService = unespService;
        this.centralService = centralService;
        this.domain = domain;
        this.ldapBaseName = LdapUtils.newLdapName("dc=" + domain.replaceAll("\\.", ",dc="));
        log.debug("Domain {} -> {}", domain, ldapBaseName);
    }

    public DirContextOperations createUser(String username, TokenVO token) throws InterruptedException, ExecutionException {
        if (username.contains("@")) {
            username = username.split("@", 2)[0];
        }
        var centralUser = centralService.getUserLogin(token);
        var servidorPublico = unespService.buscarServidorPublico(username);
        var alunoGraduacao = unespService.buscarAlunoGraduacao(username);
        var alunoPosGraduacao = unespService.buscarAlunoPosGraduacao(username);
        if (servidorPublico.get() != null) {
            return createUserServidorPublico(centralUser, servidorPublico.get());
        } else if (alunoPosGraduacao.get() != null) {
            return createUserAlunoPosGraduacao(centralUser, alunoPosGraduacao.get());
        } else if (alunoGraduacao.get() != null) {
            return createUserAlunoGraduacao(centralUser, alunoGraduacao.get());
        }
        return null;
    }

    private DirContextOperations createUserServidorPublico(UsuarioVO centralUser, ServidorPublicoVO servidorPublico) {
        log.info("Criando usuário para Servidor Público");
        var dn = LdapUtils.prepend(
                LdapUtils.newLdapName(String.format("CN=%s,OU=%s,OU=UNIDADMS,OU=GROUPS,OU=%s",
                        centralUser.getName(),
                        servidorPublico.getLotacaoPrestacao().getSigla(),
                        servidorPublico.getLotacaoPrestacao().getUnidadeUniversitaria().getSigla())),
                ldapBaseName);
        DirContextAdapter context = new DirContextAdapter(dn);
        context.setAttributeValues("objectclass", new String[] { "top", "person", "organizationalPerson", "user" });
        context.setAttributeValue("cn", centralUser.getName());
        context.setAttributeValue("sAMAccountName", servidorPublico.getMatricula());
        context.setAttributeValue("userPrincipalName", centralUser.getName() + '@' + domain);
        context.setAttributeValue("displayName", centralUser.getDetails().getNome());
        context.setAttributeValue("department", limit(servidorPublico.getLotacaoPrestacao().getNome(), 64));
        context.setAttributeValue("company", limit(servidorPublico.getLotacaoPrestacao().getUnidadeUniversitaria().getNome(), 64));
        context.setAttributeValue("name", centralUser.getName());
        context.setAttributeValue("employeeID", String.valueOf(centralUser.getDetails().getIdUsuario()));
        return context;
    }

    private DirContextOperations createUserAlunoGraduacao(UsuarioVO centralUser, AlunoGraduacaoVO alunoGraduacaoVO) {
        log.info("Criando usuário para Aluno Graduação");
        var dn = LdapUtils.prepend(ldapBaseName,
                LdapUtils.newLdapName(String.format("CN=%s,OU=%s,OU=CURSOS,OU=GROUPS,OU=%s",
                        centralUser.getName(),
                        alunoGraduacaoVO.getCursoVO().getSigla(),
                        alunoGraduacaoVO.getUnidadeVO().getSigla())));
        DirContextAdapter context = new DirContextAdapter(dn);
        context.setAttributeValues("objectclass", new String[] { "top", "person", "organizationalPerson", "user" });
        context.setAttributeValue("cn", centralUser.getName());
        context.setAttributeValue("sAMAccountName", centralUser.getName());
        context.setAttributeValue("userPrincipalName", centralUser.getName() + '@' + domain);
        context.setAttributeValue("displayName", centralUser.getDetails().getNome());
        context.setAttributeValue("department", limit(alunoGraduacaoVO.getCursoVO().getNome(), 64));
        context.setAttributeValue("company", limit(alunoGraduacaoVO.getUnidadeVO().getNome(), 64));
        context.setAttributeValue("name", centralUser.getName());
        context.setAttributeValue("employeeID", String.valueOf(centralUser.getDetails().getIdUsuario()));
        return context;
    }

    private DirContextOperations createUserAlunoPosGraduacao(UsuarioVO centralUser, AlunoStrictoSensuVO alunoStrictoSensuVO) {
        log.info("Criando usuário para Aluno Pós-Graduação");
        var dn = LdapUtils.prepend(ldapBaseName,
                LdapUtils.newLdapName(String.format("CN=%s,OU=%s,OU=CURSOS,OU=GROUPS,OU=%s",
                        centralUser.getName(),
                        alunoStrictoSensuVO.getProgramaVO().getSigla(),
                        alunoStrictoSensuVO.getUnidadeVO().getSigla())));
        DirContextAdapter context = new DirContextAdapter(dn);
        context.setAttributeValues("objectclass", new String[] { "top", "person", "organizationalPerson", "user" });
        context.setAttributeValue("cn", centralUser.getName());
        context.setAttributeValue("sAMAccountName", centralUser.getName());
        context.setAttributeValue("userPrincipalName", centralUser.getName() + '@' + domain);
        context.setAttributeValue("displayName", centralUser.getDetails().getNome());
        context.setAttributeValue("department", limit(alunoStrictoSensuVO.getProgramaVO().getNome(), 64));
        context.setAttributeValue("company", limit(alunoStrictoSensuVO.getUnidadeVO().getNome(), 64));
        context.setAttributeValue("name", centralUser.getName());
        context.setAttributeValue("employeeID", String.valueOf(centralUser.getDetails().getIdUsuario()));
        return context;
    }

    private static String limit(String str, int size) {
        if (str == null) {
            return null;
        }
        if (size == 0) {
            return "";
        }
        if (str.length() > size) {
            return str.substring(0, size);
        }
        return str;
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

}
