package com.conny.oauthjwt.module.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.conny.oauthjwt.module.auth.domain.MemberEntity;
import com.conny.oauthjwt.security.oauth2.model.OAuth2Provider;

public interface MemberRepository extends JpaRepository<MemberEntity, Long> {
	Optional<MemberEntity> findByOauth2IdAndProvider(String oauthId, OAuth2Provider provider);
}
