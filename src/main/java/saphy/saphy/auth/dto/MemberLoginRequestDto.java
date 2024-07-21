package saphy.saphy.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MemberLoginRequestDto {

    @NotBlank(message = "아이디를 입력해주세요!")
    private String loginId;

    @NotBlank(message = "비밀번호를 입력해주세요!")
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$", message = "비밀번호는 8자 이상 영어와 숫자를 포함한 형식입니다!")
    private String password;
}
