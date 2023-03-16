package com.conny.oauthjwt.module.auth.domain.constant;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum RoleType {
	USER("ROLE_USER"),
	MANAGER("ROLE_MANAGER"),
	DEVELOPER("ROLE_DEVELOPER"),
	ADMIN("ROLE_ADMIN");

	private final String roleName;

}
