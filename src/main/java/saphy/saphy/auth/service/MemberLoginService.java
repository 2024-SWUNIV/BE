package saphy.saphy.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import saphy.saphy.auth.dto.LoginResponseDto;
import saphy.saphy.auth.utils.JwtUtil;
import saphy.saphy.member.domain.Member;
import saphy.saphy.auth.dto.MemberLoginRequestDto;
import saphy.saphy.member.domain.repository.MemberRepository;
import saphy.saphy.global.exception.SaphyException;
import saphy.saphy.global.exception.ErrorCode;

@Service
@RequiredArgsConstructor
public class MemberLoginService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtUtil jwtUtil;

    @Value("${spring.jwt.token-validity}")
    private Long tokenValidity;

    public LoginResponseDto login(MemberLoginRequestDto loginDto) {

        Member member = validateLoginId(loginDto.getLoginId());
        // 토큰 생성 - refresh 유효시간 변경 필요
        String accessToken = jwtUtil.createJwt("access", loginDto.getLoginId(), tokenValidity);
        String refreshToken = jwtUtil.createJwt("refresh", loginDto.getLoginId(), tokenValidity);

        // 로그인 응답 객체 반환
        return new LoginResponseDto(accessToken, refreshToken);
    }

    private Member validateLoginId(String loginId) {
        return memberRepository.findByLoginId(loginId)
                .orElseThrow(() -> SaphyException.from(ErrorCode.MEMBER_NOT_FOUND, "사용자를 찾을 수 없습니다."));
    }

    private void checkPassword(String rawPassword, String encodedPassword) {
        if (!bCryptPasswordEncoder.matches(rawPassword, encodedPassword)) {
            throw SaphyException.from(ErrorCode.INCORRECT_PASSWORD, "비밀번호가 일치하지 않습니다!");
        }
    }
}
