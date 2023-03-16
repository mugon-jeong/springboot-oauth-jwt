package com.conny.oauthjwt.config.jwt.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.conny.oauthjwt.config.UserContext;
import com.conny.oauthjwt.config.jwt.model.ServerTokenEntity;
import com.conny.oauthjwt.config.jwt.repository.ServerTokenRepository;
import com.conny.oauthjwt.module.auth.domain.MemberEntity;
import com.conny.oauthjwt.module.auth.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenService {
	private final ServerTokenRepository serverTokenRepository;
	private final MemberRepository memberRepository;

	/**
	 * 리프레쉬 토큰을 DB 에 저장한다. <br>
	 * 만약 같은 사용자가 같은 기기에 이미 리프레쉬 토큰을 생성한 이력이 있는 경우에는 해당 토큰의 값을 갱신한다.
	 * @param userContext 사용자
	 * @param token 저장할 토큰 값
	 * @param clientIp 사용자 접속 IP
	 * @param userAgent 사용자 접속 기기 정보
	 * @return id 생성된 토큰 식별자
	 */
	public Long saveRefreshToken(UserContext userContext, String token, String clientIp, String userAgent) {
		// TODO exception
		MemberEntity member = memberRepository.findById(userContext.memberIdx()).orElseThrow();
		Optional<ServerTokenEntity> byDevice = serverTokenRepository.findByMember_IdAndClientIpAndAndUserAgent(
			member.getId(), clientIp, userAgent);

		if (byDevice.isPresent()) {
			ServerTokenEntity findRefreshToken = byDevice.get();
			findRefreshToken.changeToken(token);
			return findRefreshToken.getId();
		}

		ServerTokenEntity newRefreshToken = ServerTokenEntity.of(member, token, clientIp, userAgent);
		serverTokenRepository.save(newRefreshToken);
		return newRefreshToken.getId();
	}
}
