package saphy.saphy.member.domain.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import saphy.saphy.member.domain.SocialType;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MemberJoinRequestDto {

    @NotBlank(message = "아이디는 필수입니다!")
    private String loginId;

    @NotBlank(message = "비밀번호는 필수입니다!")
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$", message = "비밀번호는 8자 이상 영어와 숫자를 포함 해야합니다")
    private String password;

    @NotBlank(message = "이름은 필수입니다!")
    private String name;

    private String address;

    @NotBlank(message = "전화번호는 필수입니다!")
    private String phoneNumber;

    private String email;

    @Builder.Default
    private SocialType socialType = SocialType.LOCAL;

    // 권한 부여는 별도의 관리자 기능을 통해 처리 예정
    @Builder.Default
    private Boolean isAdmin = false;
}
