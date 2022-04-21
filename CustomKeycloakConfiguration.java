
package org.demo.config;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Retention(value = RUNTIME)
@Target(value = { TYPE })
@Configuration
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
@EnableWebSecurity
public @interface  CustomKeycloakConfiguration {
    
}
