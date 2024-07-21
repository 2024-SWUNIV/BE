package saphy.saphy.auth.presentation;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import saphy.saphy.auth.dto.LoginResponseDto;
import saphy.saphy.auth.dto.MemberLoginRequestDto;
import saphy.saphy.auth.service.MemberLoginService;
import saphy.saphy.global.exception.ErrorCode;
import saphy.saphy.global.exception.SaphyException;
import saphy.saphy.global.response.ApiResponse;

@RestController
@RequiredArgsConstructor
@RequestMapping // api 결정되면 수정 필요
public class MemberLoginController {

    private final MemberLoginService memberLoginService;

    @PostMapping("/login")
    public ApiResponse<LoginResponseDto> login(@Validated @RequestBody MemberLoginRequestDto loginDto, Errors errors){
        validateRequest(errors);
        LoginResponseDto ApiResponse = memberLoginService.login(loginDto);
        return new ApiResponse<>(ApiResponse, ErrorCode.REQUEST_OK);
    }

    private void validateRequest(Errors errors) {
        if (errors.hasErrors()) {
            errors.getFieldErrors().forEach(error -> {
                String errorMessage = error.getDefaultMessage();
                throw SaphyException.from(ErrorCode.INVALID_REQUEST, errorMessage);
            });
        }
    }
}
