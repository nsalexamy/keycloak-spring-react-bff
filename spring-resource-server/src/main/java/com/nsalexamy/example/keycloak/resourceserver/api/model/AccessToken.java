package com.nsalexamy.example.keycloak.resourceserver.api.model;

public record AccessToken(String principal, String accessToken, String authorities, String scope) {

}
