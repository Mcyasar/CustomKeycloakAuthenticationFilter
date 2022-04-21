package org.demo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.AdapterDeploymentContextFactoryBean;
import org.keycloak.adapters.springsecurity.config.KeycloakSpringConfigResolverWrapper;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import org.demo.impl.AuthenticationComponent;
import org.demo.UserService;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;

@CustomKeycloakConfiguration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter 
{

    @Autowired
    private UserService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthenticationComponent authComponent;

    @Autowired
    private ApplicationProperties applicationProperties;

    @Autowired(required = false)
    private KeycloakConfigResolver keycloakConfigResolver;

    @Value("${keycloak.configurationFile:WEB-INF/keycloak.json}")
    private Resource keycloakConfigFileResource;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public KeycloakSpringBootConfigResolver KeycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    protected AdapterDeploymentContext adapterDeploymentContext() throws Exception {
        AdapterDeploymentContextFactoryBean factoryBean;
        if (keycloakConfigResolver != null) {
             factoryBean = new AdapterDeploymentContextFactoryBean(new KeycloakSpringConfigResolverWrapper(keycloakConfigResolver));
        }
        else {
            factoryBean = new AdapterDeploymentContextFactoryBean(keycloakConfigFileResource);
        }
        factoryBean.afterPropertiesSet();
        return factoryBean.getObject();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http   
        .cors().and()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        .authorizeRequests()
        .anyRequest().permitAll().and()      
        .csrf().disable();

        http.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
    }

    public OncePerRequestFilter authenticationTokenFilterBean() throws Exception {
        return new JwtFilter(authenticationManagerBean(), new CustomKeycloakAuthenticationProcessingFilter(authenticationManagerBean(), adapterDeploymentContext()), userDetailsService, jwtUtil, authComponent, crossSiteIgnoredPathList(), applicationProperties);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/v3/api-docs",
                        "/actuator/health/**",
                        "/swagger-ui/**",
                        "/swagger-ui.html",
                        "/configuration/ui",
                        "/swagger-resources/**",
                        "/configuration/**",
                        "/configuration/security",
                        "/webjars/**") ;
    }

    @Bean
    List<Pair<HttpMethod, String>> crossSiteIgnoredPathList(){
        List<Pair<HttpMethod, String>> list = new ArrayList<>();
        list.add(Pair.of(HttpMethod.POST, SecurityConstants.SIGN_UP_URL));
        list.add(Pair.of(HttpMethod.DELETE, "/authenticate"));
        list.add(Pair.of(HttpMethod.DELETE, "/login"));
        return list;
    }


    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.addAllowedHeader("Content-Type");
        configuration.addAllowedHeader("transaction");
        configuration.addAllowedHeader("X-Requested-With");
        configuration.addAllowedHeader("Authorization");
        configuration.addAllowedHeader("Listener");
        configuration.addAllowedHeader("SendMessage");
        configuration.addAllowedHeader("project");
        configuration.addAllowedHeader("Access-Control-Allow-Origin");
        configuration.addAllowedHeader("Access-Control-Allow-Credentials");
        configuration.addAllowedHeader("Access-Control-Expose-Headers");

        configuration.addExposedHeader("Content-Type");
        configuration.addExposedHeader("transaction");
        configuration.addExposedHeader("project");
        configuration.addExposedHeader("Access-Control-Allow-Origin");
        configuration.addExposedHeader("Access-Control-Allow-Credentials");
        configuration.addExposedHeader("Access-Control-Expose-Headers");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
