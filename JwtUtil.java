package org.demo.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtUtil {

    @Autowired
    ApplicationProperties applicationProperties;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(applicationProperties.getJwtSecretKey()).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    public String generateTokenHalfExpiration(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createTokenHalfExpiration(claims, userDetails.getUsername());
    }

    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createRefreshToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        
        return Jwts.builder().setClaims(claims)
                .setSubject(subject) // ilgili kullanıcı
                .setIssuedAt(new Date(System.currentTimeMillis()))                
                .setExpiration(new Date(System.currentTimeMillis() + applicationProperties.getJwtTimeout()))
                .signWith(SignatureAlgorithm.HS256, applicationProperties.getJwtSecretKey())
                .compact();
    }

    private String createTokenHalfExpiration(Map<String, Object> claims, String subject) {
        
        return Jwts.builder().setClaims(claims)
                .setSubject(subject) // ilgili kullanıcı
                .setIssuedAt(new Date(System.currentTimeMillis()))                
                .setExpiration(new Date(System.currentTimeMillis() + (applicationProperties.getJwtTimeout()/2)))
                .signWith(SignatureAlgorithm.HS256, applicationProperties.getJwtSecretKey())
                .compact();
    }

    private String createRefreshToken(Map<String, Object> claims, String subject) {
        
        return Jwts.builder().setClaims(claims)
                .setSubject(subject) // ilgili kullanıcı
                .setIssuedAt(new Date(System.currentTimeMillis()))                
                .setExpiration(new Date(System.currentTimeMillis() + applicationProperties.getJwtTimeout()))
                .signWith(SignatureAlgorithm.HS256, applicationProperties.getJwtSecretKey())
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    
}
