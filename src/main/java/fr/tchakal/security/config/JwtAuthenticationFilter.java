package fr.tchakal.security.config;

import fr.tchakal.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.beans.Transient;
import java.io.IOException;
import java.security.Security;

import jakarta.transaction.TransactionScoped;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        //si on fait appel a l'endpoint de l'authentification alors on passe pour le filtre suivant
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        //vérifier si le header n'est vide et commence bien avec le mot 'Bearer '
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            //si oui ; passer pour le filtre suivant
            filterChain.doFilter(request, response);
            return;
        }
        //extracter le token (7 caracteres pour bearer et l'espace
        jwt = authHeader.substring(7);
        //extracter le username
        userEmail = jwtService.extractUsername(jwt);
        //vérifier si l'utilisateur n'est pas déjà connecté
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //charger l'utilisateur a partir de la base de données
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            //vérifier si le token n'est pas expiré et n'est pas révoqué
            var isTokenValid = tokenRepository.findByToken(jwt)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);
            //vérfier si l'utilisateur est valide
            if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
                //Créer un un objet de type UsernamePasswordAuthenticationToken pour l'utilisateur les privilèges et les profils
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                //setter details avec la requete
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //mettre à jour le token
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        //passer pour le filtre suivant
        filterChain.doFilter(request, response);
    }
}
