package com.nsalexamy.example.keycloak.gateway.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/user")
@Slf4j
public class UserController {

    public static final String ANONYMOUS_USER = "anonymousUser";

//    @Value("${app.auth.post-login-redirect}")
//    private String postLoginRedirect;



    @GetMapping("/login")
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        var cookies = request.getCookies();

        if(cookies != null) {
            log.info("=====> cookies: {}", Arrays.asList(cookies));
        }

//        log.info("Redirecting to: {}", postLoginRedirect);
//        response.sendRedirect(postLoginRedirect);
    }

    //    @GetMapping("/logout")
//    public void logout(HttpServletResponse response, HttpSession session) throws IOException {
//        session.invalidate();
//    }
//    @Operation(
//            summary = "Authenticated",
//            description = "Returns true if user is authenticated",
//            security = {
//                    @SecurityRequirement(name = "bearer-key")
//            }
//    )
    @GetMapping("/authenticated")
    public boolean authenticated() {

        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        log.debug("authenticated authentication name: {}", name);

        if(ANONYMOUS_USER.equals(name)) {
            return false;
        }

        return SecurityContextHolder.getContext().getAuthentication().isAuthenticated();
    }

//    @Operation(
//            summary = "Username",
//            description = "Returns user's principal name",
//            security = {
//                    @SecurityRequirement(name = "bearer-key")
//            }
//    )
    @GetMapping("/username")
    public Map<String, String> username(Authentication authentication) {
        String username = authentication.getName();
        log.info("username: {}",username);
        return Map.of("username", username);
    }


//    @Operation(
//            summary = "Profile",
//            description = "Returns user's profile",
//            security = {
//                    @SecurityRequirement(name = "bearer-key")
//            }
//    )
    @GetMapping("/profile")
    public Map<String, Object> idToken(@AuthenticationPrincipal OidcUser oidcUser) {
        log.info("oidcUser: {}", oidcUser);
        log.info("id token: {}", oidcUser.getIdToken().getTokenValue());

        if(oidcUser == null) {
            return Map.of("error", "No id_token found", "id_token", null);

        } else {
            return oidcUser.getClaims();
        }
    }
}

