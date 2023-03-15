package com.conny.oauthjwt.common;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.format.annotation.DateTimeFormat.ISO;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
@EntityListeners(AuditingEntityListener.class)
@MappedSuperclass
public class AuditingFields {

	/** 생성일시 */
	@DateTimeFormat(iso = ISO.DATE_TIME)
	@CreatedDate
	@Column(nullable = false, updatable = false)
	protected LocalDateTime createdAt;

	/** 수정일시 */
	@DateTimeFormat(iso = ISO.DATE_TIME)
	@LastModifiedDate
	@Column(nullable = false)
	protected LocalDateTime modifiedAt;
}
