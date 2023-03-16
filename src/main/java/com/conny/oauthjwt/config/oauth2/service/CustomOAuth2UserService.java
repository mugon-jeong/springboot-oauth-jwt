package com.conny.oauthjwt.config.oauth2.service;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.conny.oauthjwt.config.UserContext;
import com.conny.oauthjwt.config.oauth2.CustomOAuth2User;
import com.conny.oauthjwt.config.oauth2.model.OAuth2Provider;
import com.conny.oauthjwt.config.oauth2.model.OAuth2UserInfo;
import com.conny.oauthjwt.config.oauth2.model.OAuth2UserInfoFactory;
import com.conny.oauthjwt.module.auth.domain.MemberEntity;
import com.conny.oauthjwt.module.auth.domain.constant.RoleType;
import com.conny.oauthjwt.module.auth.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
	private final MemberRepository memberRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		OAuth2Provider provider = OAuth2Provider.valueOf(registrationId.toUpperCase(Locale.ROOT));
		OAuth2User oAuth2User = delegate.loadUser(userRequest);
		Map<String, Object> attributes = oAuth2User.getAttributes();
		OAuth2UserInfo userInfo = OAuth2UserInfoFactory.createUserInfo(provider, attributes);
		//UserRepository에서 email, provider로 유저 검색
		Optional<MemberEntity> optionalMember = memberRepository.findByOauth2IdAndProvider(
			userInfo.getOAuth2Id(), provider);
		MemberEntity memberEntity = optionalMember.orElseGet(
			() -> memberRepository.save(MemberEntity.from(userInfo, Set.of(RoleType.USER))));
		return new CustomOAuth2User(userInfo,
			UserContext.of(memberEntity.getId(), memberEntity.getNickname(), provider, memberEntity.getRoleTypes()));
	}
}
