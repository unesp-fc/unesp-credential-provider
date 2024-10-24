package br.unesp.fc.credential;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class UnespCredentialProvider {

    private static ConfigurableApplicationContext context;

    public static void main(String[] args) {
        SpringApplication.run(UnespCredentialProvider.class, args);
    }

    // Start service method
    public static void start(String args[]) {
        context = SpringApplication.run(UnespCredentialProvider.class, args);
    }

    // Stop service method
    public static void stop(String args[]) {
        SpringApplication.exit(context);
    }

}
