package com.conny.oauthjwt.security.jwt.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * <h1>JwtExpiredTokenException</h1>
 * <p>
 *     JWT 토큰 만료 시 발생한다.
 * </p>
 * @see com.auth0.jwt.exceptions.TokenExpiredException
 */
public class JwtExpiredTokenException extends AuthenticationException {
	public JwtExpiredTokenException(String msg, Throwable cause) {
		super(msg, cause);
	}

	public JwtExpiredTokenException(String msg) {
		super(msg);
	}
}
