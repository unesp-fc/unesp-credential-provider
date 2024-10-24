package br.unesp.fc.credential.vo;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import lombok.Data;

@Data
public class OAuth2Error implements Serializable{

    String error;

    @JsonProperty("error_description")
    String errorDescription;

}
