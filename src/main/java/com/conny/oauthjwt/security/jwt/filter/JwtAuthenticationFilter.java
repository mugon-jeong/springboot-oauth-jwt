package com.conny.oauthjwt.security.jwt.filter;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.conny.oauthjwt.security.jwt.token.JwtAuthenticationToken;

import jakarta.servlet.FilterChain;
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
	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final String BEARER_PREFIX = "Bearer ";
	private final Logger log = LoggerFactory.getLogger(getClass());

	public JwtAuthenticationFilter(RequestMatcher requestMatcher) {
		super(requestMatcher);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException {
		String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);
		log.info("authorizationHeader :{}", authorizationHeader);
		// 인증 헤더가 없는 경우 익명 사용자로 간주 (Anonymous Authentication)
		if (Objects.isNull(authorizationHeader)) {

			return new AnonymousAuthenticationToken(UUID.randomUUID().toString(),
				"anonymous",
				List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
		}
		// Bearer 접두어 제거
		String token = authorizationHeader.substring(BEARER_PREFIX.length());
		log.info("token :{}", token);
		JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(token);

		// provider를 실행하는 부분
		return this.getAuthenticationManager().authenticate(authenticationToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authResult) throws IOException, ServletException {
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authResult);
		SecurityContextHolder.setContext(context);
		chain.doFilter(request, response);
	}
}
