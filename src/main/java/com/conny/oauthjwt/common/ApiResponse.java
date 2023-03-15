package com.conny.oauthjwt.common;

import lombok.Builder;

@Builder
public record ApiResponse<T>(
	Integer code, // 1 성공, -1 실패, 99 관리자 성공, -99 관리자 실패
	String msg,
	T data
) {

	public static <T> ApiResponse<T> of(Integer code, String msg, T data) {
		return ApiResponse.<T>builder().code(code).msg(msg).data(data).build();
	}
}
