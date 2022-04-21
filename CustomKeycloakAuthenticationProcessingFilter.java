package org.demo.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.KeycloakAuthenticationException;
import org.keycloak.adapters.springsecurity.authentication.RequestAuthenticatorFactory;
import org.keycloak.adapters.springsecurity.authentication.SpringSecurityRequestAuthenticatorFactory;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.token.AdapterTokenStoreFactory;
import org.keycloak.adapters.springsecurity.token.SpringSecurityAdapterTokenStoreFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

public class CustomKeycloakAuthenticationProcessingFilter extends KeycloakAuthenticationProcessingFilter{

    private AuthenticationManager authenticationManager;
    private AdapterDeploymentContext customAdapterDeploymentContext;
    private AdapterTokenStoreFactory customAdapterTokenStoreFactory = new SpringSecurityAdapterTokenStoreFactory();
    private RequestAuthenticatorFactory customRequestAuthenticatorFactory = new SpringSecurityRequestAuthenticatorFactory();

    public CustomKeycloakAuthenticationProcessingFilter(AuthenticationManager authenticationManager, AdapterDeploymentContext customAdapterDeploymentContext) {
        super(authenticationManager);
        this.authenticationManager = authenticationManager;
        this.customAdapterDeploymentContext = customAdapterDeploymentContext;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException{
        final String sessionType = request.getHeader("LoginType");
        Authentication authentication = null;

        if(SecurityContextHolder.getContext().getAuthentication() == null && sessionType != null && sessionType.equals("oidc")){
            HttpFacade facade = new SimpleHttpFacade(request, response);
            KeycloakDeployment deployment = customAdapterDeploymentContext.resolveDeployment(facade);
            
            deployment.setDelegateBearerErrorResponseSending(true);

            AdapterTokenStore tokenStore = customAdapterTokenStoreFactory.createAdapterTokenStore(deployment, request, response);
            RequestAuthenticator authenticator
                    = customRequestAuthenticatorFactory.createRequestAuthenticator(facade, request, deployment, tokenStore, -1);

            AuthOutcome result = authenticator.authenticate();

            if (AuthOutcome.FAILED.equals(result)) {
                AuthChallenge challenge = authenticator.getChallenge();
                if (challenge != null) {
                    challenge.challenge(facade);
                }
                throw new KeycloakAuthenticationException("Invalid authorization header, see WWW-Authenticate header for details");
            }

            if (AuthOutcome.NOT_ATTEMPTED.equals(result)) {
                AuthChallenge challenge = authenticator.getChallenge();
                if (challenge != null) {
                    challenge.challenge(facade);
                }
                if (deployment.isBearerOnly()) {
                    throw new KeycloakAuthenticationException("Authorization header not found,  see WWW-Authenticate header");
                } else {
                    // let continue if challenged, it may redirect
                    return null;
                }
            }

            else if (AuthOutcome.AUTHENTICATED.equals(result)) {
                authentication = SecurityContextHolder.getContext().getAuthentication();
                Assert.notNull(authentication, "Authentication SecurityContextHolder was null");
                return authenticationManager.authenticate(authentication);
            }
            else {
                AuthChallenge challenge = authenticator.getChallenge();
                if (challenge != null) {
                    challenge.challenge(facade);
                }
                return null;
            }
            }else{            
                authentication = SecurityContextHolder.getContext().getAuthentication();
            }
        
        return authentication;

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        chain.doFilter(request, response);
    }
    
}
