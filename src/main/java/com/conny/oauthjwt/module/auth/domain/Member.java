package com.conny.oauthjwt.module.auth.domain;

import java.util.Set;

import com.conny.oauthjwt.module.auth.domain.constant.RoleType;

public record Member(
	Long id,
	String email,
	String nickname,
	Set<RoleType> roleTypes
) {
	public static Member of(Long id, String nickname, Set<RoleType> roleTypes) {
		return Member.of(id, null, nickname, roleTypes);
	}

	public static Member of(Long id, String email, String nickname, Set<RoleType> roleTypes) {
		return new Member(id, email, nickname, roleTypes);
	}
}
