package org.demo.config;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.representations.AccessToken;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import org.demo.UserDetailsExtend;
import org.demo.AuthenticationComponent;
import org.demo.UserService;
import org.demo.ErrorMessageUtil;
import org.demo.ErrorMessage;


public class JwtFilter extends OncePerRequestFilter {
    
    private ApplicationProperties applicationProperties;
    private UserService userDetailsService;
    private JwtUtil jwtUtil;
    private AuthenticationComponent authComponent;
    private List<Pair<HttpMethod, String>> crossSiteIgnoredPathList = null;
    private AuthenticationManager authenticationManager;
    private KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter;

    public JwtFilter(AuthenticationManager authenticationManager, KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter, UserService userDetailsService, JwtUtil jwtUtil, AuthenticationComponent authComponent, ApplicationProperties applicationProperties) {
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
        this.authComponent = authComponent;
        this.applicationProperties = applicationProperties;
        this.authenticationManager = authenticationManager;
        this.keycloakAuthenticationProcessingFilter = keycloakAuthenticationProcessingFilter;
    }

    public JwtFilter(AuthenticationManager authenticationManager, KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter, UserService userDetailsService, JwtUtil jwtUtil, AuthenticationComponent authComponent, List<Pair<HttpMethod, String>> crossSiteIgnoredPathList, ApplicationProperties applicationProperties) {
        this(authenticationManager, keycloakAuthenticationProcessingFilter, userDetailsService, jwtUtil, authComponent, applicationProperties);
        this.crossSiteIgnoredPathList = crossSiteIgnoredPathList;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        
        final String authHeader = request.getHeader("Authorization");
        final String refreshToken = request.getHeader("RefreshToken");
        final String sessionType = request.getHeader("LoginType");

        boolean isOICDRequest = false;

        String username = null;
        String jwt = null;
        String refreshJwt = null;
        UserDetails userDetails = null;

        response.setCharacterEncoding("UTF-8");

        if(sessionType != null && sessionType.equals("oidc")){
            try{
                isOICDRequest = true;
                keycloakAuthenticationProcessingFilter.setAuthenticationManager(authenticationManager);
                Authentication externalAuth = keycloakAuthenticationProcessingFilter.attemptAuthentication(request, response);
                KeycloakPrincipal<?> principal = ((KeycloakPrincipal<?>)externalAuth.getPrincipal());
                AccessToken token = principal.getKeycloakSecurityContext().getToken();
                username = token.getPreferredUsername();
                userDetails = userDetailsService.loadUserByUsername(username);
                if(userDetails == null){
                    userDetails = new UserDetailsExtend(username, token.getEmail(), null, true, true, true, true, null);
                    ((UserDetailsExtend)userDetails).setUniqident(UUID.randomUUID());
                }
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken tkn = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), null);                
                context.setAuthentication(tkn);                
                SecurityContextHolder.setContext(context);       
                request.setAttribute(UsernamePasswordAuthenticationToken.class.getName(), context);        
            }catch(Exception ex){
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                ErrorMessage errorMessage = ErrorMessageUtil
                        .createErrorMessageJson("OICD UNAUTHORIZED.", HttpStatus.UNAUTHORIZED);
                PrintWriter responseWriter = response.getWriter();
                responseWriter.write(errorMessage.toJsonString());
                return;
            }            
        }
        
        
        if (!isOICDRequest && authHeader != null && !authHeader.isEmpty()) {
            jwt = authHeader;
            if (authHeader.startsWith("Bearer ")) {
                jwt = authHeader.substring(7);
            }

            if (refreshToken != null) {
                refreshJwt = refreshToken;
                if (refreshToken.startsWith("Bearer ")) {
                    refreshJwt = refreshToken.substring(7);
                }

                try {
                    jwtUtil.extractExpiration(refreshJwt);
                    username = jwtUtil.extractUsername(refreshJwt);
                    if (username == null || username.isEmpty()) {
                        response.setStatus(HttpStatus.NOT_FOUND.value());
                        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        ErrorMessage errorMessage = ErrorMessageUtil
                                .createErrorMessageJson("Kullanıcı adı bulunamamıştır.", HttpStatus.NOT_FOUND);
                        PrintWriter responseWriter = response.getWriter();
                        responseWriter.write(errorMessage.toJsonString());
                        return;
                    }

                    try {
                        userDetails = userDetailsService.loadUserByUsername(username);
                    } catch (UsernameNotFoundException e) {
                        if (userDetails == null) {
                            response.setStatus(HttpStatus.NOT_FOUND.value());
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            ErrorMessage errorMessage = ErrorMessageUtil.createErrorMessageJson(
                                    "Kullanıcı bilgileri bulunamamıştır.", HttpStatus.NOT_FOUND);
                            PrintWriter responseWriter = response.getWriter();
                            responseWriter.write(errorMessage.toJsonString());
                            return;
                        }
                    }
                } catch (ExpiredJwtException e) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    ErrorMessage errorMessage = ErrorMessageUtil.createErrorMessageJson("Session süresi dolmuştur.",
                            HttpStatus.UNAUTHORIZED, "E_TIME_OUT");
                    PrintWriter responseWriter = response.getWriter();
                    responseWriter.write(errorMessage.toJsonString());
                    return;
                }
              
                long minutes = 0;
                try {
                    minutes = TimeUnit.MILLISECONDS
                            .toMinutes(jwtUtil.extractExpiration(jwt).getTime() - new Date().getTime());
                } catch (ExpiredJwtException e) {
                    minutes = TimeUnit.MILLISECONDS
                            .toMinutes(e.getClaims().getExpiration().getTime() - new Date().getTime());
                }

                if (minutes < 0) {
                    // jwt'nin bitiş süresi refreshToken'in bitiş süresinin yarısı kadar ayarlanır
                    jwt = jwtUtil.generateTokenHalfExpiration(userDetails);
                    refreshJwt = jwtUtil.generateRefreshToken(userDetails);
                    response.setHeader("Authorization", jwt);
                    response.setHeader("RefreshToken", refreshJwt);
                }
            } else {
              
                long minutes = 0;
                try {
                    
                    minutes = TimeUnit.MILLISECONDS
                            .toMinutes(jwtUtil.extractExpiration(jwt).getTime() - new Date().getTime());
                    username = jwtUtil.extractUsername(jwt);
                    if (username == null || username.isEmpty()) {
                        response.setStatus(HttpStatus.NOT_FOUND.value());
                        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        ErrorMessage errorMessage = ErrorMessageUtil
                                .createErrorMessageJson("Kullanıcı adı bulunamamıştır.", HttpStatus.NOT_FOUND);
                        PrintWriter responseWriter = response.getWriter();
                        responseWriter.write(errorMessage.toJsonString());
                        return;
                    }

                    try {
                        userDetails = userDetailsService.loadUserByUsername(username);
                    } catch (UsernameNotFoundException e) {
                        if (userDetails == null) {
                            response.setStatus(HttpStatus.NOT_FOUND.value());
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            ErrorMessage errorMessage = ErrorMessageUtil.createErrorMessageJson(
                                    "Kullanıcı bilgileri bulunamamıştır.", HttpStatus.NOT_FOUND);
                            PrintWriter responseWriter = response.getWriter();
                            responseWriter.write(errorMessage.toJsonString());
                            return;
                        }
                    }

                } catch (ExpiredJwtException e) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    ErrorMessage errorMessage = ErrorMessageUtil.createErrorMessageJson("Session süresi dolmuştur.",
                            HttpStatus.UNAUTHORIZED, "E_TIME_OUT");
                    PrintWriter responseWriter = response.getWriter();
                    responseWriter.write(errorMessage.toJsonString());
                    return;
                } catch(IllegalArgumentException e){
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    ErrorMessage errorMessage = ErrorMessageUtil.createErrorMessageJson("JWT çözümlenemedi.",
                            HttpStatus.UNAUTHORIZED, "E_JWT_PARSE");
                    PrintWriter responseWriter = response.getWriter();
                    responseWriter.write(errorMessage.toJsonString());
                    return;
                }
              
                if (minutes <= applicationProperties.getJwtTimeout() / 4) {                    
                    jwt = jwtUtil.generateToken(userDetails);
                    response.setHeader("Authorization", jwt);
                }
            }
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null) {

            if(userDetails == null){
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                ErrorMessage errorMessage = ErrorMessageUtil.createErrorMessageJson("User not found.",
                        HttpStatus.UNAUTHORIZED, "E_USER_NOT_FOUND");
                PrintWriter responseWriter = response.getWriter();
                responseWriter.write(errorMessage.toJsonString());
                return;
            }

            authComponent.setUserDetails(userDetails);

            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

        }

        filterChain.doFilter(request, response);

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request)
      throws ServletException {
        String path = request.getRequestURI();
        String method = request.getMethod();
        
        if(crossSiteIgnoredPathList == null){
            return false;
        }

        for(Pair<HttpMethod, String> pair : crossSiteIgnoredPathList){
            if( (pair.getFirst() == null || 
                 (pair.getFirst() != null && pair.getFirst().matches(method)))
                 && path.contains(pair.getSecond())
              ){
                 return true;
              }
        }

        return false;
    }

}
