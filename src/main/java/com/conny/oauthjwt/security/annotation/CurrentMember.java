package com.conny.oauthjwt.security.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.core.annotation.AuthenticationPrincipal;

/**
 * <h1>@CurrentMember</h1>
 * <p>
 *     Security Context 내의 인증 토큰 에서 User 객체를 바로 가져오도록 하는 어노테이션.
 *     Security Context 내에 익명 인증 토큰이 있는 경우, 즉 로그인이 되지 않은 경우 null 이 주입되므로 주의해야한다.
 *     이 어노테이션으로 가져온 Member 객체는 jpa 에 영속화되지 않은 상태이며 DB 상에서 조회한 것이 아니다.
 *     따라서 해당 객체를 영속화 할 경우 문제가 발생할 수 있다.
 * </p>
 * <p>사용 예</p>
 * <pre>
 * <b>&#64;GetMapping("/")</b>
 * public String sample(<b>@CurrentMember</b> Member member) {
 *     ...
 * }
 *
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
@Documented
@AuthenticationPrincipal(expression = "#this == 'anonymous' ? null : member")
public @interface CurrentMember {
}
