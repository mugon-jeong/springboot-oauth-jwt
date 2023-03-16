package com.conny.oauthjwt.config.jwt.model;

import com.conny.oauthjwt.module.auth.domain.MemberEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * <h1>ServerToken</h1>
 * <p>
 *     JWT 서버 토큰 엔티티 <br>
 *     로그인 이후 액세스 토큰 갱신을 위해 DB 에 저장되는 리프레쉬 토큰 엔티티
 * </p>
 */
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Table(name = "SERVER_TOKEN")
@Entity
public class ServerTokenEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "REFRESH_TOKEN_ID")
	private Long id;

	@ManyToOne
	@JoinColumn(name = "USER_ID")
	private MemberEntity member;

	@Column(name = "REFRESH_TOKEN_VALUE")
	private String token;

	@Column(name = "CLIENT_IP")
	private String clientIp;

	@Column(name = "USER_AGENT")
	private String userAgent;

	public ServerTokenEntity(MemberEntity member, String token, String clientIp, String userAgent) {
		this.member = member;
		this.token = token;
		this.clientIp = clientIp;
		this.userAgent = userAgent;
	}

	public static ServerTokenEntity of(MemberEntity member, String token, String clientIp, String userAgent) {
		return new ServerTokenEntity(member, token, clientIp, userAgent);
	}

	/**
	 * 리프레쉬 토큰의 토큰 값을 변경한다.
	 * @param token 변경할 토큰 값
	 */
	public void changeToken(String token) {
		this.token = token;
	}
}
