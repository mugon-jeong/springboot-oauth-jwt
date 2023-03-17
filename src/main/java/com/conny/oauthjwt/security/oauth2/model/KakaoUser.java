package com.conny.oauthjwt.security.oauth2.model;

import java.util.Map;

import com.conny.oauthjwt.security.oauth2.dto.KakaoOauth2Response;

public class KakaoUser extends OAuth2UserInfo {
	private final String oauth2Id;
	private final String email;
	private final String nickname;

	protected KakaoUser(Map<String, Object> attributes) {
		super(attributes);
		KakaoOauth2Response kakaoOauth2Response = KakaoOauth2Response.from(attributes);
		this.email = kakaoOauth2Response.email();
		this.oauth2Id = String.valueOf(kakaoOauth2Response.id());
		this.nickname = kakaoOauth2Response.nickname();
	}

	@Override
	public String getOAuth2Id() {
		return this.oauth2Id;
	}

	@Override
	public String getEmail() {
		return this.email;
	}

	@Override
	public String getNickName() {
		return this.nickname;
	}

	@Override
	public OAuth2Provider getOAuth2Provider() {
		return OAuth2Provider.KAKAO;
	}
}
