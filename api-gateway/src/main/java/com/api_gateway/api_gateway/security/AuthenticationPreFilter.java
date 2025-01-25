package com.api_gateway.api_gateway.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

@Component
public class AuthenticationPreFilter extends AbstractGatewayFilterFactory<AuthenticationPreFilter.Config> {

    @Value("${jwt.secret}")
    private String secretKey;

    private final ObjectMapper objectMapper;
    private final List<String> excludedUrls; // FIX: Se inyecta correctamente

    @Autowired
    public AuthenticationPreFilter(ObjectMapper objectMapper, @Qualifier("excludedUrls") List<String> excludedUrls) {
        super(Config.class);
        this.objectMapper = objectMapper;
        this.excludedUrls = excludedUrls;
    }

    public static class Config {
        private List<String> excludedPatterns;

        public List<String> getExcludedPatterns() {
            return excludedPatterns;
        }

        public void setExcludedPatterns(List<String> excludedPatterns) {
            this.excludedPatterns = excludedPatterns;
        }
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            HttpHeaders httpHeaders = request.getHeaders();
            String token = httpHeaders.getFirst(HttpHeaders.AUTHORIZATION);

            // Si la URL está excluida, se deja pasar la solicitud sin validación
            if (isExcluded(path)) {
                return chain.filter(exchange);
            }

            // Validar la presencia del token
            if (token == null || !token.startsWith("Bearer ")) {
                return handleAuthError(exchange, "Missing or invalid Authorization Header", HttpStatus.UNAUTHORIZED);
            }


            token = token.substring(7); // Eliminar "Bearer " del token

            try {
                // Extraer claims del token
                Claims claims = extractAllClaims(token);

                String username = claims.getSubject();
                String role = claims.get("role", String.class);

                // Agregar los datos extraídos a los headers de la solicitud
                ServerHttpRequest modifiedRequest = request.mutate()
                        .header("username", username)
                        .header("role", role)
                        .build();

                return chain.filter(exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                return handleAuthError(exchange, "Invalid Token", HttpStatus.UNAUTHORIZED);
            }
        };
    }

    // Método mejorado para verificar si la URL está excluida
    private boolean isExcluded(String path) {
        return excludedUrls.stream().anyMatch(path::matches);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Mono<Void> handleAuthError(ServerWebExchange exchange, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("timestamp", ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        responseBody.put("message", message);
        responseBody.put("status", status.value());
        responseBody.put("errorCode", status.value());

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(responseBody);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
