package com.tutorial.jwt.config;

import com.tutorial.jwt.jwt.JwtAccessDeniedHandler;
import com.tutorial.jwt.jwt.JwtAuthenticationEntryPoint;
import com.tutorial.jwt.jwt.JwtSecurityConfig;
import com.tutorial.jwt.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// 추가 설정을 위해 WebSecurityConfiurer implements 도 가능

@EnableWebSecurity // Web 보안 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true) // @PreAuthorize 를 메소드 단위로 추가하기 위해 사용
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final TokenProvider tokenProvider;
    // private final CorsFilter corsFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            // CorsFilter corsFilter,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        // this.corsFilter = corsFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring() // 아래 요청은 무시
                .antMatchers("/h2-console/**", "/favicon.ico");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // enable h2-console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests() // HttpServletRequest를 사용하는 요청에 대한 접근 제한 설정
                .antMatchers("/api/hello").permitAll() // 이 요청은 인증 없이 접근 허용
                .antMatchers("/api/authenticate").permitAll() // 로그인
                .antMatchers("/api/signup").permitAll() // 회원 가입
                .anyRequest().authenticated() // 나머지 요청은 인증 필요

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }
}
