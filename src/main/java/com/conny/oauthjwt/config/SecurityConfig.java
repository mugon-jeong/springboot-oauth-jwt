package com.conny.oauthjwt.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.conny.oauthjwt.config.jwt.util.JwtUtil;
import com.conny.oauthjwt.config.oauth2.handler.OAuth2AuthenticationSuccessHandler;
import com.conny.oauthjwt.config.oauth2.service.CustomOAuth2UserService;
import com.conny.oauthjwt.config.util.CustomResponseUtil;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableConfigurationProperties({SecurityConfigProperties.class})
@RequiredArgsConstructor
public class SecurityConfig {
	private final SecurityConfigProperties securityConfigProperties;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public JwtUtil jwtUtil() {
		return new JwtUtil(this.securityConfigProperties.jwt());
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, CustomOAuth2UserService oAuth2UserService,
		OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler) throws
		Exception {
		return http
			.headers(configurer -> configurer.frameOptions().disable()) // iframe 허용안함
			.csrf(AbstractHttpConfigurer::disable) // csrf 허용안함
			.cors(configurer -> configurer.configurationSource(configurationSource())) // cors 재정의
			.sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.formLogin(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable)
			// ExcpetionTranslationFilter (인증 확인 필터)
			.exceptionHandling(configurer -> configurer.authenticationEntryPoint((request, response, authException) ->
				CustomResponseUtil.fail(response, "로그인을 진행해 주세요", HttpStatus.UNAUTHORIZED)))
			// 권한 실패
			.exceptionHandling(configurer -> configurer.accessDeniedHandler((request, response, e) ->
				CustomResponseUtil.fail(response, "권한이 없습니다", HttpStatus.FORBIDDEN)))
			// OAuth2 filter chain configuration
			.oauth2Login(oauth -> oauth
				.userInfoEndpoint(userInfo -> userInfo
					.userService(oAuth2UserService))
				.successHandler(oAuth2AuthenticationSuccessHandler)
			)
			.authorizeHttpRequests(auth -> {
				auth.anyRequest().authenticated();
			})
			.build();
	}

	public CorsConfigurationSource configurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.addAllowedHeader("*");
		configuration.addAllowedMethod("*");

		configuration.addAllowedOriginPattern("*"); // 프론트 서버의 주소 등록
		configuration.setAllowCredentials(true); // 클라이언트에서 쿠키 요청 허용
		configuration.addExposedHeader("Authorization");
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
