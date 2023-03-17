package com.conny.oauthjwt.security;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.conny.oauthjwt.module.auth.domain.Member;
import com.conny.oauthjwt.module.auth.domain.constant.RoleType;
import com.conny.oauthjwt.security.oauth2.model.OAuth2Provider;

public record UserContext(
	Member member,
	OAuth2Provider provider,
	Collection<? extends GrantedAuthority> getAuthorities
) implements UserDetails {

	public static UserContext of(Member member, OAuth2Provider provider,
		Collection<? extends GrantedAuthority> authorities) {
		return new UserContext(
			member,
			provider,
			authorities
		);
	}

	public static UserContext of(Member member, OAuth2Provider provider) {
		return new UserContext(
			member,
			provider,
			member.roleTypes().stream()
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
		return String.valueOf(this.member.id());
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
