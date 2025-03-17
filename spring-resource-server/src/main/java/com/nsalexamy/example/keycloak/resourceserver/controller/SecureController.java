package com.nsalexamy.example.keycloak.resourceserver.controller;

import com.nsalexamy.example.keycloak.resourceserver.api.model.AccessToken;
import com.nsalexamy.example.keycloak.resourceserver.api.model.Message;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/secure")
public class SecureController {
    @PreAuthorize("hasAnyRole('NSA2_USER', 'NSA2_ADMIN')")
//    @PreAuthorize("hasAuthority('NSA2_USER')")
//    @PreAuthorize("hasAuthority('SCOPE_nsa2.user.*')")
    @GetMapping("/hello")
    public Message hello(Principal principal, JwtAuthenticationToken jwtToken) {
        log.info("principal: {}", principal);
        log.info("name: {}", jwtToken.getName());
        log.info("principal class: {}", principal.getClass());
        log.info("jwtToken class: {}", jwtToken.getClass());
        log.info("authorities: {}", jwtToken.getAuthorities());
//        return Map.of("message", "ResourceServer - Hello, " + principal.getName());
        return new Message("ResourceServer - Hello, " + principal.getName());
    }

    @PreAuthorize("hasRole('NSA2_ADMIN')")
//    @PreAuthorize("hasAuthority('NSA2_ADMIN')")
//    @Secured("ROLE_NSA2_ADMIN")
//    @PreAuthorize("hasAuthority('SCOPE_nsa2.admin')")
    @GetMapping("/admin/hello")
    public Message adminHello(Principal principal) {
        //return Map.of("message", "ResourceServer - Admin Hello, " + principal.getName());
        return new Message("ResourceServer - Admin Hello, " + principal.getName());
    }

    @GetMapping("/access_token")
    public AccessToken accessToken(JwtAuthenticationToken jwtToken) {

        Map<String, Object> tokenAttributes = jwtToken.getTokenAttributes();
        log.info("principal class: {}", jwtToken.getPrincipal().getClass());

        if(jwtToken.getPrincipal() instanceof DefaultOidcUser oidcUser) {
            log.info("oidcUser: {}", oidcUser);
        } else {
            log.info("is not instance of DefaultOidcUser");
        }

        var authorities = jwtToken.getAuthorities();
        log.info("authorities: {}", authorities);
//        return Map.of(
//                "principal", jwtToken.getName(),
//                "access_token", jwtToken.getToken().getTokenValue(),
//                "authorities", authorities.toString(),
//                "scope",tokenAttributes.containsKey("scope") ?
//                        tokenAttributes.get("scope").toString() : ""
//        );
        return new AccessToken(jwtToken.getName(), jwtToken.getToken().getTokenValue(), authorities.toString(),
                tokenAttributes.containsKey("scope") ? tokenAttributes.get("scope").toString() : "");
    }
}
