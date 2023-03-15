package com.conny.oauthjwt.config.oauth2;

import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import com.conny.oauthjwt.config.oauth2.model.OAuth2UserInfo;
import com.conny.oauthjwt.module.auth.domain.MemberEntity;
import com.conny.oauthjwt.module.auth.domain.constant.RoleType;

import lombok.Getter;

@Getter
public class CustomOAuth2User extends DefaultOAuth2User {
	private final MemberEntity memberEntity;

	/**
	 * OAuth2 사용자 정보, 사용자 계정 기반으로 CustomOAuth2User 객체를 생성할때 사용하는 생성자
	 * @param oAuth2UserInfo OAuth2 사용자 정보 객체
	 * @param memberEntity OAuth2 계정 정보를 기반으로 생성/조회한 사용자 계정 엔티티
	 */
	public CustomOAuth2User(OAuth2UserInfo oAuth2UserInfo, MemberEntity memberEntity) {
		super(memberEntity.getRoleTypes().stream()
				.map(RoleType::name)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toUnmodifiableSet()), oAuth2UserInfo.getAttributes(),
			memberEntity.getProvider().getAttributeKey());
		this.memberEntity = memberEntity;
	}

	// 시큐리티 컨텍스트 내의 인증 정보를 가져와 하는 작업을 수행할 경우 계정 식별자가 사용되도록 조치
	@Override
	public String getName() {
		return String.valueOf(memberEntity.getId());
	}

}
