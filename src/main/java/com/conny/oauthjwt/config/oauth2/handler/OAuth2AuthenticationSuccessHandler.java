package com.conny.oauthjwt.config.oauth2.handler;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import com.conny.oauthjwt.config.oauth2.CustomOAuth2User;
import com.conny.oauthjwt.module.auth.domain.MemberEntity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {
	@Value("${app.oauth2.authorized-redirect-uri}")
	private String redirectUrl;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(authentication);
		CustomOAuth2User oauth2User = (CustomOAuth2User)authentication.getPrincipal();
		MemberEntity memberEntity = oauth2User.getMemberEntity();

		// TODO access token 생성

		// TODO refresh token 생성

		// TODO 리프레쉬 토큰 DB 저장 (저장시 사용자의 접속 기기 정보를 고려함)

		String redirectUri = UriComponentsBuilder
			.fromUriString(redirectUrl)
			.queryParam("access_token", "accessToken")
			.queryParam("refresh_token", "refreshToken")
			.toUriString();

		response.sendRedirect(redirectUri);
	}
}
