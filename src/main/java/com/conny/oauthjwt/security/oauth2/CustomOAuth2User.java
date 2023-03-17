package com.conny.oauthjwt.security.oauth2;

import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import com.conny.oauthjwt.security.UserContext;
import com.conny.oauthjwt.security.oauth2.model.OAuth2UserInfo;

import lombok.Getter;

@Getter
public class CustomOAuth2User extends DefaultOAuth2User {
	private final UserContext userContext;

	/**
	 * OAuth2 사용자 정보, 사용자 계정 기반으로 CustomOAuth2User 객체를 생성할때 사용하는 생성자
	 * @param oAuth2UserInfo OAuth2 사용자 정보 객체
	 * @param userContext OAuth2 계정 정보를 기반으로 생성/조회한 사용자 계정 정보
	 */
	public CustomOAuth2User(OAuth2UserInfo oAuth2UserInfo, UserContext userContext) {
		super(userContext.getAuthorities(), oAuth2UserInfo.getAttributes(), userContext.provider().getAttributeKey());
		this.userContext = userContext;
	}

	// 시큐리티 컨텍스트 내의 인증 정보를 가져와 하는 작업을 수행할 경우 계정 식별자가 사용되도록 조치
	@Override
	public String getName() {
		return String.valueOf(userContext.member().id());
	}

}
