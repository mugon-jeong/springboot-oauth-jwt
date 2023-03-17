package com.conny.oauthjwt.security.jwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.conny.oauthjwt.security.jwt.model.ServerTokenEntity;

public interface ServerTokenRepository extends JpaRepository<ServerTokenEntity, Long> {

	Optional<ServerTokenEntity> findByMember_IdAndClientIpAndAndUserAgent(Long memberIdx, String clientIp,
		String userAgent);

	Optional<ServerTokenEntity> findByToken(String token);
}
