package com.conny.oauthjwt.security.jwt.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import com.conny.oauthjwt.security.UserContext;

/**
 * <h1>JwtAuthenticationToken</h1>
 * <p>
 *     JWT 인증을 위한 객체
 *     provider에서 인증 대상
 * </p>
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
	private final UserContext userContext;
	private final String token;

	/**
	 * JWT 토큰으로 인증 전 객체를 생성하는 생성자
	 * @param token jwt 토큰
	 */
	public JwtAuthenticationToken(String token) {
		super(null);
		this.userContext = null;
		this.token = token;
		this.setAuthenticated(false);
	}

	/**
	 * JWT 토큰으로 인증 후 객체를 생성하는 생성자
	 * @param userContext 유저 정보
	 * @param token jwt 토큰
	 */
	public JwtAuthenticationToken(String token, UserContext userContext) {
		super(userContext.getAuthorities());
		this.userContext = userContext;
		this.token = token;
		this.setAuthenticated(true);
	}

	// 토큰으로 인증
	@Override
	public Object getCredentials() {
		return token;
	}

	// 인증 후 유저 정보 전달
	@Override
	public Object getPrincipal() {
		return userContext;
	}
}
