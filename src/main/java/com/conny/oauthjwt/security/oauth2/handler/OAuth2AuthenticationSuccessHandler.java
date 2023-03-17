package com.conny.oauthjwt.security.oauth2.handler;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import com.conny.oauthjwt.common.util.ClientUtils;
import com.conny.oauthjwt.security.SecurityConfigProperties;
import com.conny.oauthjwt.security.jwt.service.TokenService;
import com.conny.oauthjwt.security.jwt.token.TokenType;
import com.conny.oauthjwt.security.jwt.util.JwtUtil;
import com.conny.oauthjwt.security.oauth2.CustomOAuth2User;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final SecurityConfigProperties securityConfigProperties;
	private final TokenService tokenService;
	private final JwtUtil jwtUtil;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(authentication);
		CustomOAuth2User oauth2User = (CustomOAuth2User)authentication.getPrincipal();
		// access token 생성
		String accessToken = jwtUtil.create(oauth2User.getUserContext(), TokenType.ACCESS_TOKEN);

		// 리프레쉬 토큰 DB 저장 (저장시 사용자의 접속 기기 정보를 고려함)
		String ip = ClientUtils.getClientIpAddressIfServletRequestExist();
		String userAgent = request.getHeader("User-Agent");
		String refreshToken = tokenService.saveRefreshToken(oauth2User.getUserContext(), ip, userAgent);

		String redirectUri = UriComponentsBuilder
			.fromUriString(securityConfigProperties.oauth2().authorizedRedirectUri())
			.queryParam("access_token", accessToken)
			.queryParam("refresh_token", refreshToken)
			.toUriString();

		response.sendRedirect(redirectUri);
	}
}
