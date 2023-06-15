package fr.tchakal.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "3fGxcYNeHnXQcaRqZ2I6AOZQTuTfAG5kQGIYjgzr+h+SWR4gzafrF/HK/e5OypJWGGqAj9c8vje4QPGpIxYy9+1ZFDfVeEDlenV/banQpXi34WzSuRnEZUJyPQxnippulIq8ep1kGt7tl7/I+Jn2bu8SUKhHixe+JmRSbRd5t58ZrdRhzusrL9TTvOI6n585d20u+O9HM6Tn1ETm+p+boZ93YAVwBi5YGDdKZ+Z5MqEIgIkfnHUXQ9w8JdUbrLHljQPNlQftn4skR94ruzGgLkD7my9hGHLI7ouUqcU3vxBhKZftcta5FvQwuFUw6aQZN4UVAn31j3qqM1+J8NOdibRzyh0L9B/jUq9GXThx6SM=";

    public String extractUsername(String jwt) {
        return extractClaim(jwt, Claims::getSubject);
    }

    public <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwt);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String jwt) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) //expire dans 24h
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String jwt, UserDetails userDetails) {
        final String username = extractUsername(jwt);
        return (username.equals(userDetails.getUsername())) && isTokenExpired(jwt);
    }

    private boolean isTokenExpired(String jwt) {
        return extractExpiration(jwt).before(new Date());
    }

    private Date extractExpiration(String jwt) {
        return extractClaim(jwt,Claims::getExpiration);
    }
}
