package saphy.saphy.auth.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import saphy.saphy.auth.Repository.RefreshTokenRepository;
import saphy.saphy.auth.filter.CustomLogoutFilter;
import saphy.saphy.auth.filter.JwtFilter;
import saphy.saphy.auth.filter.LoginFilter;
import saphy.saphy.auth.utils.JwtUtil;
import saphy.saphy.member.domain.repository.MemberRepository;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;
    private final MemberRepository memberRepository;
    private final RefreshTokenRepository refreshTokenRepository;

//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return web -> web.ignoring().anyRequest();
//    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors((cors) -> cors
                        .configurationSource(new CorsConfigurationSource() {

                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                CorsConfiguration configuration = new CorsConfiguration();

                                // 허용되는 출처 설정
                                configuration.setAllowedOrigins(List.of("https://localhost:8080"));

                                // 허용되는 HTTP 메서드 설정, "*"는 모든 메서드를 허용
                                configuration.setAllowedMethods(Collections.singletonList("*"));

                                // 자격 증명(쿠키, 인증 헤더 등)을 포함한 요청을 허용
                                configuration.setAllowCredentials(true);

                                // 허용되는 요청 헤더 설정, "*"는 모든 헤더를 허용
                                configuration.setAllowedHeaders(Collections.singletonList("*"));

                                // CORS 설정의 캐시 시간 설정 - 3600초(1시간)
                                configuration.setMaxAge(3600L);

                                // 클라이언트에 노출할 헤더 설정, 여기서는 "Authorization" 헤더
                                configuration.setExposedHeaders(List.of("Authorization"));

                                // 구성된 CORS 설정 반환
                                return configuration;
                            }
                        }));


        http
                .csrf(AbstractHttpConfigurer::disable);

        http
                .formLogin(AbstractHttpConfigurer::disable);

        http
                .httpBasic(AbstractHttpConfigurer::disable);

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/join","/reissue" ,"/").permitAll()
                        // swagger 관련 접근 허용 - 서비스 모델에서는 삭제
                        .requestMatchers("/swagger-ui.html","/v3/api-docs","/swagger-resources/**","/webjars/**").permitAll()
                        .anyRequest().authenticated());

        http
                // 커스텀한 필터들 적용
                .addFilterBefore(new JwtFilter(jwtUtil, memberRepository), LoginFilter.class)
                .addFilterAt(
                        new LoginFilter(authenticationManager(authenticationConfiguration), refreshTokenRepository, jwtUtil,
                                "/api/login"),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshTokenRepository), LogoutFilter.class);

        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}