package com.conny.oauthjwt.config.jwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.conny.oauthjwt.config.jwt.model.ServerTokenEntity;

public interface ServerTokenRepository extends JpaRepository<ServerTokenEntity, Long> {

	Optional<ServerTokenEntity> findByMember_IdAndClientIpAndAndUserAgent(Long memberIdx, String clientIp,
		String userAgent);
}
