package com.conny.oauthjwt.security.jwt.filter;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.conny.oauthjwt.security.jwt.dto.TokenResponse;
import com.conny.oauthjwt.security.jwt.exception.JwtExpiredTokenException;
import com.conny.oauthjwt.security.jwt.exception.JwtModulatedTokenException;
import com.conny.oauthjwt.security.jwt.service.TokenService;
import com.conny.oauthjwt.security.util.CustomResponseUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * <h1>JwtRefreshFilter</h1>
 * <p>
 * Access Token 갱신 담당 필터
 * </p>
 *
 */
@RequiredArgsConstructor
public class JwtRefreshFilter extends OncePerRequestFilter {
	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final String BEARER_PREFIX = "Bearer ";
	private final Logger log = LoggerFactory.getLogger(getClass());
	private final TokenService tokenService;
	private final RequestMatcher requestMatcher;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		if (requestMatcher.matches(request)) {
			String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);
			String token = authorizationHeader.substring(BEARER_PREFIX.length());
			try {
				TokenResponse tokenRefresh = tokenService.tokenRefresh(token);
				// 성공 시의 응답
				CustomResponseUtil.success(response, tokenRefresh);
			} catch (TokenExpiredException expired) {
				throw new JwtExpiredTokenException("만료된 JWT 토큰입니다.");
			} catch (JWTVerificationException verificationException) {
				throw new JwtModulatedTokenException("변조된 JWT 토큰입니다.");
			}

		} else {
			filterChain.doFilter(request, response);
		}

	}
}
