package com.conny.oauthjwt.config.jwt.filter;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * <h1>JwtAuthenticationFilter</h1>
 * <p>
 *     인증이 필요한 요청이 들어올 경우 해당 필터가 JWT 토큰을 이용해 인증처리한다.
 * </p>
 */
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	public JwtAuthenticationFilter(RequestMatcher requestMatcher) {
		super(requestMatcher);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException,
		IOException,
		ServletException {
		return null;
	}
}
