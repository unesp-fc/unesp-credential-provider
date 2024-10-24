package br.unesp.fc.credential.vo;

import java.io.Serializable;
import lombok.Data;

@Data
public class UsuarioVO implements Serializable {

    private DetailsVO details;
    private String name;
    private Boolean authenticate;

    @Data
    public static class DetailsVO implements Serializable {

        private Long idUsuario;
        private String email;
        private String nome;
        private String cpf;

    }

}
