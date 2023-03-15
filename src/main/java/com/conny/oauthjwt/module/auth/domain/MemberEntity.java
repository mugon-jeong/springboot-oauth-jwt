package com.conny.oauthjwt.module.auth.domain;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import org.hibernate.annotations.SQLDelete;

import com.conny.oauthjwt.common.AuditingFields;
import com.conny.oauthjwt.config.oauth2.model.OAuth2Provider;
import com.conny.oauthjwt.config.oauth2.model.OAuth2UserInfo;
import com.conny.oauthjwt.module.auth.domain.constant.RoleType;
import com.conny.oauthjwt.module.auth.domain.converter.RoleTypesConverter;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "member", indexes = {
	@Index(name = "member_id_idx", columnList = "MEMBER_ID"),
	@Index(columnList = "MEMBER_EMAIL"),
	@Index(columnList = "MEMBER_OAUTH2_ID"),
})
@SQLDelete(sql = "UPDATE \"member\" SET deleted_at = NOW() where idx=?")
@Entity
public class MemberEntity extends AuditingFields {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "MEMBER_ID")
	private Long id;

	@Column(name = "MEMBER_OAUTH2_ID")
	private String oauth2Id;

	@Column(name = "MEMBER_EMAIL")
	private String email;

	@Column(name = "MEMBER_NICKNAME")
	private String nickname;

	@Column(name = "MEMBER_OAUTH2_PROVIDER")
	@Enumerated(EnumType.STRING)
	private OAuth2Provider provider;

	@Convert(converter = RoleTypesConverter.class)
	@Column(nullable = false)
	private Set<RoleType> roleTypes = new LinkedHashSet<>();

	@Builder
	public MemberEntity(String oauth2Id, String email, String nickname, OAuth2Provider provider,
		Set<RoleType> roleTypes) {
		this.oauth2Id = oauth2Id;
		this.email = email;
		this.nickname = nickname;
		this.provider = provider;
		this.roleTypes = roleTypes;
	}

	public static MemberEntity of(String oauth2Id, String email, String nickname, OAuth2Provider provider,
		Set<RoleType> roleTypes) {
		return MemberEntity.builder()
			.oauth2Id(oauth2Id)
			.email(email)
			.nickname(nickname)
			.provider(provider)
			.roleTypes(roleTypes)
			.build();
	}

	public static MemberEntity from(OAuth2UserInfo userInfo, Set<RoleType> roleTypes) {
		return MemberEntity.of(
			userInfo.getOAuth2Id(),
			userInfo.getEmail(),
			userInfo.getNickName(),
			userInfo.getOAuth2Provider(),
			roleTypes
		);
	}

	public void addRoleType(RoleType roleType) {
		this.getRoleTypes().add(roleType);
	}

	public void addRoleTypes(Collection<RoleType> roleTypes) {
		this.getRoleTypes().addAll(roleTypes);
	}

	public void removeRoleType(RoleType roleType) {
		this.getRoleTypes().remove(roleType);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof MemberEntity that)) {
			return false;
		}
		return this.id != null && this.id.equals(that.id);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.id);
	}
}
