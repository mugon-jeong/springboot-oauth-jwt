package com.conny.oauthjwt.security.jwt.service;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.conny.oauthjwt.module.auth.domain.MemberEntity;
import com.conny.oauthjwt.module.auth.repository.MemberRepository;
import com.conny.oauthjwt.security.UserContext;
import com.conny.oauthjwt.security.jwt.dto.TokenResponse;
import com.conny.oauthjwt.security.jwt.exception.JwtExpiredTokenException;
import com.conny.oauthjwt.security.jwt.exception.JwtModulatedTokenException;
import com.conny.oauthjwt.security.jwt.model.ServerTokenEntity;
import com.conny.oauthjwt.security.jwt.repository.ServerTokenRepository;
import com.conny.oauthjwt.security.jwt.token.TokenType;
import com.conny.oauthjwt.security.jwt.util.JwtUtil;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenService {
	private final ServerTokenRepository serverTokenRepository;
	private final MemberRepository memberRepository;
	private final JwtUtil jwtUtil;

	/**
	 * 리프레쉬 토큰을 DB 에 저장한다. <br>
	 * 만약 같은 사용자가 같은 기기에 이미 리프레쉬 토큰을 생성한 이력이 있는 경우에는 해당 토큰의 값을 갱신한다.
	 *
	 * @param userContext 사용자
	 * @param clientIp    사용자 접속 IP
	 * @param userAgent   사용자 접속 기기 정보
	 */
	public String saveRefreshToken(UserContext userContext, String clientIp, String userAgent) {
		// TODO exception
		MemberEntity member = memberRepository.findById(userContext.member().id()).orElseThrow();
		Optional<ServerTokenEntity> byDevice = serverTokenRepository.findByMember_IdAndClientIpAndAndUserAgent(
			member.getId(), clientIp, userAgent);
		String refreshToken = jwtUtil.create(userContext, TokenType.REFRESH_TOKEN);
		if (byDevice.isPresent()) {
			ServerTokenEntity findRefreshToken = byDevice.get();
			findRefreshToken.changeToken(refreshToken);
			return refreshToken;
		}

		serverTokenRepository.save(ServerTokenEntity.of(member, refreshToken, clientIp, userAgent));
		return refreshToken;
	}

	public TokenResponse tokenRefresh(String token) {
		try {
			UserContext userContext = jwtUtil.verify(token, TokenType.REFRESH_TOKEN);
			ServerTokenEntity tokenEntity = serverTokenRepository.findByToken(token).orElseThrow();
			String accessToken = jwtUtil.create(userContext, TokenType.ACCESS_TOKEN);
			// 리프레쉬 토큰 만료가 3일이하로 남은경우 리프레쉬 토큰도 갱신 처리
			if (jwtUtil.isExpired(token, 3, ChronoUnit.DAYS, TokenType.REFRESH_TOKEN)) {
				token = jwtUtil.create(userContext, TokenType.REFRESH_TOKEN);
				tokenEntity.changeToken(token);
			}
			return new TokenResponse(accessToken, token);
		} catch (TokenExpiredException expired) {
			throw new JwtExpiredTokenException("만료된 JWT 토큰입니다.");
		} catch (JWTVerificationException verificationException) {
			throw new JwtModulatedTokenException("변조된 JWT 토큰입니다.");
		}
	}

}
