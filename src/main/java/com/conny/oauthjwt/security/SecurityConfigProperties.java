package com.conny.oauthjwt.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.extern.slf4j.Slf4j;

@ConfigurationProperties(prefix = "security")
@Slf4j
public record SecurityConfigProperties(Oauth2Configure oauth2, JwtConfigure jwt) {

	public record Oauth2Configure(
		String authorizedRedirectUri
	) {
	}

	public record JwtConfigure(
		AccessTokenProperties accessToken,
		RefreshTokenProperties refreshToken,
		String issuer
	) {

		public record AccessTokenProperties(String signKey, String header, int expirySeconds) {

		}

		public record RefreshTokenProperties(String signKey, String header, int expirySeconds) {

		}
	}
}
