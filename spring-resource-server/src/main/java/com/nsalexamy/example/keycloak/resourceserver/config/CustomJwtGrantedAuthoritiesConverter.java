package com.nsalexamy.example.keycloak.resourceserver.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @see <a href="https://medium.com/@alperkrtglu/spring-oauth2-with-keycloak-moving-from-scope-to-roles-34247f3ff78e">Spring OAuth2 with OIDC: Moving from Scope to Roles</a>
 * Converts the roles from the JWT token to a collection of GrantedAuthority
 */
@Slf4j
public class CustomJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private static final String RESOURCE_ACCESS = "resource_access";
    private static final String CLIENT_ID = "nsa2-gateway"; // Your Keycloak client ID
    private static final String ROLES = "roles";

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();


    @Override
    public <U> Converter<Jwt, U> andThen(Converter<? super Collection<GrantedAuthority>, ? extends U> after) {
        return Converter.super.andThen(after);
    }
    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        Collection<GrantedAuthority> authorities = defaultGrantedAuthoritiesConverter.convert(source);
        log.info("authorities : {}", authorities);

        var roles = source.getClaimAsStringList("roles");
        log.info("roles: {}", roles);

//        log.info("nsa2-gateway.roles: {}", source.getClaimAsStringList("nsa2-gateway.roles"));

        Map<String, Object> resourceAccess = source.getClaimAsMap(RESOURCE_ACCESS);
        if (resourceAccess != null && resourceAccess.containsKey(CLIENT_ID)) {
            Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(CLIENT_ID);
            if (clientAccess.containsKey(ROLES)) {
                List<String> clientRoles = (List<String>) clientAccess.get(ROLES);
                authorities = Stream.concat(
                        authorities.stream(),
                        clientRoles.stream().map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role).map(SimpleGrantedAuthority::new)
                ).collect(Collectors.toList());
            }
        }

        log.info("authorities : {}", authorities);

        return authorities;

//        // If roles are not present in the JWT token, then use the scopes as roles
//        if(roles == null) {
//            return source.getClaimAsStringList("scope")
//                    .stream()
//                    .map(scope -> "SCOPE_" + scope)
//                    .map(SimpleGrantedAuthority::new)
//                    .collect(Collectors.toList());
//        }
//
//        // If roles are present in the JWT token, then use the roles as roles
//        return roles.stream()
//                .map(role -> "ROLE_" + role)
//                .map(SimpleGrantedAuthority::new)
//                .collect(Collectors.toList());
    }

//    @Bean
//    public JwtAuthenticationConverter nsa2AuthenticationConverter() {
//        var converter = new JwtAuthenticationConverter();
//        converter.setJwtGrantedAuthoritiesConverter(new CustomJwtGrantedAuthoritiesConverter());
//        return converter;
//    }
}
