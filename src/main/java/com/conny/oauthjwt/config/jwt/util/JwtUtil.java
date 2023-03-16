package com.conny.oauthjwt.config.jwt.util;

import java.util.Date;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.conny.oauthjwt.config.SecurityConfigProperties;
import com.conny.oauthjwt.config.UserContext;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtUtil {
	public static final String TOKEN_PREFIX = "Bearer ";
	private static final String DELIMITER = ",";
	private final SecurityConfigProperties.JwtConfigure jwtConfigure;

	public String create(UserContext userContext, int expired) {
		String jwtToken = JWT.create()
			.withSubject(userContext.getUsername())
			.withExpiresAt(new Date(System.currentTimeMillis() + expired * 1000L))
			.withClaim("id", userContext.memberIdx())
			.withClaim("role", userContext.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.sorted()
				.collect(Collectors.joining(DELIMITER)))
			.sign(Algorithm.HMAC512(jwtConfigure.clientSecret()));
		return TOKEN_PREFIX + jwtToken;
	}

}
