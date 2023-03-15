package com.conny.oauthjwt.module.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.conny.oauthjwt.config.oauth2.model.OAuth2Provider;
import com.conny.oauthjwt.module.auth.domain.MemberEntity;

public interface MemberRepository extends JpaRepository<MemberEntity, Long> {
	Optional<MemberEntity> findByOauth2IdAndProvider(String oauthId, OAuth2Provider provider);
}
