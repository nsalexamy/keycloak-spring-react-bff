package com.nsalexamy.example.keycloak.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
@EnableAspectJAutoProxy
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth ->
                        auth
                            .requestMatchers("/actuator/**", "*/actuator/**").permitAll()
                            .anyRequest().authenticated()
//                                auth
//                        .requestMatchers("/user/**", "/secure/**").authenticated()
//                        .anyRequest().permitAll()
                )
                .oauth2Login(Customizer.withDefaults())  // Enables OAuth2 login
                .oauth2Client(Customizer.withDefaults()) // Enables OAuth2 client
                .csrf(csrf -> csrf.disable())  // Disable CSRF for APIs
                .cors(cors -> cors.configurationSource(corsConfigurationSource())); // Enable CORS

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(List.of(
                "http://auth.nsa2.com:9000",  // Keycloak
                "http://gateway.nsa2.com:8080" // Spring Cloud Gateway
        ));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
