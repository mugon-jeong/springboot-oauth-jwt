package com.conny.oauthjwt.security;

import java.util.List;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.conny.oauthjwt.security.jwt.filter.JwtAuthenticationFilter;
import com.conny.oauthjwt.security.jwt.filter.JwtRefreshFilter;
import com.conny.oauthjwt.security.jwt.matcher.FilterSkipMatcher;
import com.conny.oauthjwt.security.jwt.service.TokenService;
import com.conny.oauthjwt.security.jwt.util.JwtUtil;
import com.conny.oauthjwt.security.oauth2.handler.OAuth2AuthenticationSuccessHandler;
import com.conny.oauthjwt.security.oauth2.service.CustomOAuth2UserService;
import com.conny.oauthjwt.security.util.CustomResponseUtil;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableConfigurationProperties({SecurityConfigProperties.class})
@RequiredArgsConstructor
public class SecurityConfig {
	private final SecurityConfigProperties securityConfigProperties;

	public Filter jwtAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
		FilterSkipMatcher filterSkipMatcher = new FilterSkipMatcher(
			List.of("/api/refresh", "/api/logout"),
			List.of("/api/**")
		);
		JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(filterSkipMatcher);
		jwtAuthenticationFilter.setAuthenticationManager(authenticationManager);
		return jwtAuthenticationFilter;
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public JwtUtil jwtUtil() {
		return new JwtUtil(this.securityConfigProperties.jwt());
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http,
		CustomOAuth2UserService oAuth2UserService,
		OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
		TokenService tokenService) throws
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
			// 필터 적용
			.apply(new CustomSecurityFilterManager(tokenService)).and()
			.authorizeHttpRequests(auth -> {
				auth.requestMatchers("/api/admin").hasRole("ADMIN");
				auth.requestMatchers("/api/user").hasRole("USER");
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

	// 모든 필터 등록은 여기서!! (AuthenticationManager 순환 의존 문제로 내부 클래스로 만들어진 듯, 추측임)
	@RequiredArgsConstructor
	public class CustomSecurityFilterManager extends AbstractHttpConfigurer<CustomSecurityFilterManager, HttpSecurity> {
		private final TokenService tokenService;

		@Override
		public void configure(HttpSecurity http) throws Exception {
			// log.debug("디버그 : SecurityConfig의 configure");
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
			http.addFilterBefore(jwtAuthenticationFilter(authenticationManager),
				OAuth2AuthorizationRequestRedirectFilter.class);
			http.addFilterBefore(new JwtRefreshFilter(tokenService, new AntPathRequestMatcher("/api/refresh")),
				JwtAuthenticationFilter.class);

		}
	}
}
