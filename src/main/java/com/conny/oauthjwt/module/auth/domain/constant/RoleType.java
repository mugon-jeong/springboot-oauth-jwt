package com.conny.oauthjwt.module.auth.domain.constant;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum RoleType {
	USER,
	MANAGER,
	DEVELOPER,
	ADMIN
}
