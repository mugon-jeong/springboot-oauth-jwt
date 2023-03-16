package com.conny.oauthjwt.config;

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
		String issuer,
		String clientSecret
	) {

		public JwtConfigure(
			AccessTokenProperties accessToken,
			RefreshTokenProperties refreshToken,
			String issuer,
			String clientSecret
		) {
			this.accessToken = accessToken;
			this.refreshToken = refreshToken;
			this.issuer = issuer;
			this.clientSecret = clientSecret;
		}

		public record AccessTokenProperties(String header, int expirySeconds) {

		}

		public record RefreshTokenProperties(String header, int expirySeconds) {

		}
	}
}
