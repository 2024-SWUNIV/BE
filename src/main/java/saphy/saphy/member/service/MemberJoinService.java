package saphy.saphy.member.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import saphy.saphy.global.exception.ErrorCode;
import saphy.saphy.global.exception.SaphyException;
import saphy.saphy.member.domain.Member;
import saphy.saphy.member.domain.dto.MemberJoinRequestDto;
import saphy.saphy.member.domain.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class MemberJoinService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void join(MemberJoinRequestDto joinDto) {

        validateExistMember(joinDto);
        Member joinMember = Member.builder()
                .loginId(joinDto.getLoginId())
                .password(bCryptPasswordEncoder.encode(joinDto.getPassword()))
                .name(joinDto.getName())
                .address(joinDto.getAddress())
                .phoneNumber(joinDto.getPhoneNumber())
                .email(joinDto.getEmail())
                .socialType(joinDto.getSocialType())
                .isAdmin(joinDto.getIsAdmin())
                .build();
        memberRepository.save(joinMember);
    }

    private void validateExistMember(MemberJoinRequestDto joinDto) {
        String loginId = joinDto.getLoginId();
        if (memberRepository.existsByLoginId(loginId)) {
            throw SaphyException.from(ErrorCode.DUPLICATE_MEMBER_LOGIN_ID);
        }
    }

}
