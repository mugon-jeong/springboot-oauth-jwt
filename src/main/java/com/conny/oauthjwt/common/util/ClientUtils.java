package com.conny.oauthjwt.common.util;

import java.util.Objects;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

public class ClientUtils {

	private static final String[] IP_HEADER_CANDIDATES = {
		"X-Forwarded-For",
		"Proxy-Client-IP",
		"WL-Proxy-Client-IP",
		"HTTP_X_FORWARDED_FOR",
		"HTTP_X_FORWARDED",
		"HTTP_X_CLUSTER_CLIENT_IP",
		"HTTP_CLIENT_IP",
		"HTTP_FORWARDED_FOR",
		"HTTP_FORWARDED",
		"HTTP_VIA",
		"REMOTE_ADDR"
	};

	private ClientUtils() {
		throw new IllegalStateException("Utility class");
	}

	public static String getClientIpAddressIfServletRequestExist() {

		if (Objects.isNull(RequestContextHolder.getRequestAttributes())) {
			return "0.0.0.0";
		}

		HttpServletRequest request = ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getRequest();
		for (String header : IP_HEADER_CANDIDATES) {
			String ipFromHeader = request.getHeader(header);
			if (Objects.nonNull(ipFromHeader) && ipFromHeader.length() != 0
				&& !"unknown".equalsIgnoreCase(ipFromHeader)) {
				return ipFromHeader.split(",")[0];
			}
		}
		return request.getRemoteAddr();
	}
}
