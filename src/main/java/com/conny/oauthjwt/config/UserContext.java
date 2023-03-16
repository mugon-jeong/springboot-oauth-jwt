package com.conny.oauthjwt.config;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.conny.oauthjwt.config.oauth2.model.OAuth2Provider;
import com.conny.oauthjwt.module.auth.domain.constant.RoleType;

public record UserContext(
	Long memberIdx,
	String nickname,
	OAuth2Provider provider,
	Collection<? extends GrantedAuthority> getAuthorities
) implements UserDetails {

	public static UserContext of(Long memberIdx, String nickname, OAuth2Provider provider, Set<RoleType> roleTypes) {
		return new UserContext(
			memberIdx,
			nickname,
			provider,
			roleTypes.stream()
				.map(RoleType::getRoleName)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toUnmodifiableSet())
		);
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.getAuthorities;
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public String getUsername() {
		return this.nickname;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}
