package com.conny.oauthjwt.module.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.conny.oauthjwt.module.auth.domain.Member;
import com.conny.oauthjwt.security.annotation.CurrentMember;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api")
public class AuthController {

	@GetMapping("/user")
	public String user(@CurrentMember Member member) {
		log.info("member :{}", member);
		return "user";
	}

	@GetMapping("/admin")
	public String admin(@CurrentMember Member member) {
		log.info("member :{}", member);
		return "admin";
	}
}
