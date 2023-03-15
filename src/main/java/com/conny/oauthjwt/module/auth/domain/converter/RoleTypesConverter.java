package com.conny.oauthjwt.module.auth.domain.converter;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import com.conny.oauthjwt.module.auth.domain.constant.RoleType;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter()
public class RoleTypesConverter implements AttributeConverter<Set<RoleType>, String> {

	private static final String DELIMITER = ",";

	@Override
	public String convertToDatabaseColumn(Set<RoleType> attribute) {
		return attribute.stream().map(RoleType::name).sorted()
			.collect(Collectors.joining(DELIMITER));
	}

	@Override
	public Set<RoleType> convertToEntityAttribute(String dbData) {
		// update 쿼리 등을 위해 변경가능하게 toUnmodifiableSet이 아니라 toSet으로 반환
		return Arrays.stream(dbData.split(DELIMITER)).map(RoleType::valueOf)
			.collect(Collectors.toSet());
	}
}
