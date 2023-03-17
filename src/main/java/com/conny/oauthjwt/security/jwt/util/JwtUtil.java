package com.conny.oauthjwt.security.jwt.util;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.conny.oauthjwt.module.auth.domain.Member;
import com.conny.oauthjwt.module.auth.domain.constant.RoleType;
import com.conny.oauthjwt.security.SecurityConfigProperties;
import com.conny.oauthjwt.security.UserContext;
import com.conny.oauthjwt.security.jwt.token.TokenType;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtUtil {
	private static final String DELIMITER = ",";
	private final SecurityConfigProperties.JwtConfigure jwtConfigure;

	public String create(UserContext userContext, TokenType tokenType) {
		return JWT.create()
			.withSubject(userContext.getUsername())
			.withExpiresAt(new Date(System.currentTimeMillis() + expired(tokenType) * 1000L))
			.withClaim("id", userContext.member().id())
			.withClaim("nickname", userContext.member().nickname())
			.withArrayClaim("roles",
				userContext.member().roleTypes().stream().map(RoleType::name).toArray(String[]::new))
			.sign(Algorithm.HMAC512(signKey(tokenType)));
	}

	public UserContext verify(String token, TokenType tokenType) {
		DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(signKey(tokenType))).build().verify(token);
		Long id = decodedJWT.getClaim("id").asLong();
		Set<RoleType> roles = Arrays.stream(decodedJWT.getClaim("roles").asArray(String.class))
			.map(RoleType::valueOf)
			.collect(Collectors.toUnmodifiableSet());
		String nickname = decodedJWT.getClaim("nickname").asString();
		Member member = Member.of(id, nickname, roles);
		return UserContext.of(member, null);
	}

	public boolean isExpired(String token, long time, ChronoUnit timeUnit, TokenType tokenType) {
		DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(signKey(tokenType))).build().verify(token);
		Instant exp = decodedJWT.getExpiresAt().toInstant();
		Instant now = Instant.now();
		long diff = now.until(exp, timeUnit);
		return diff < time;
	}

	public int expired(TokenType tokenType) {
		return switch (tokenType) {

			case ACCESS_TOKEN -> jwtConfigure.accessToken().expirySeconds();
			case REFRESH_TOKEN -> jwtConfigure.refreshToken().expirySeconds();
		};
	}

	public String signKey(TokenType tokenType) {
		return switch (tokenType) {
			case ACCESS_TOKEN -> jwtConfigure.accessToken().signKey();
			case REFRESH_TOKEN -> jwtConfigure.refreshToken().signKey();
		};
	}

}
