package com.conny.oauthjwt.security.jwt.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.conny.oauthjwt.security.UserContext;
import com.conny.oauthjwt.security.jwt.exception.JwtExpiredTokenException;
import com.conny.oauthjwt.security.jwt.exception.JwtModulatedTokenException;
import com.conny.oauthjwt.security.jwt.token.JwtAuthenticationToken;
import com.conny.oauthjwt.security.jwt.token.TokenType;
import com.conny.oauthjwt.security.jwt.util.JwtUtil;

import lombok.RequiredArgsConstructor;

/**
 * <h1>JwtAuthenticationProvider</h1>
 * <p>
 *     JWT 토큰 문자열을 검증하고 계정 엔티티로 바꾸는 작업을 관리한다.
 * </p>
 */
@RequiredArgsConstructor
@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
	private final JwtUtil jwtUtil;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String token = (String)authentication.getCredentials();
		try {
			UserContext userContext = jwtUtil.verify(token, TokenType.ACCESS_TOKEN);
			return new JwtAuthenticationToken(token, userContext);
		} catch (TokenExpiredException expired) {
			throw new JwtExpiredTokenException("만료된 JWT 토큰입니다.");
		} catch (JWTVerificationException verificationException) {
			throw new JwtModulatedTokenException("변조된 JWT 토큰입니다.");
		}
	}

	// JwtAuthenticationToken 타입만 처리 가능하도록 설정
	@Override
	public boolean supports(Class<?> authentication) {
		return JwtAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
