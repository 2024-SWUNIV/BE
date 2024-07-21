package saphy.saphy.member.presentation;

import lombok.RequiredArgsConstructor;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import saphy.saphy.global.exception.ErrorCode;
import saphy.saphy.global.exception.SaphyException;
import saphy.saphy.global.response.ApiResponse;
import saphy.saphy.member.domain.Member;
import saphy.saphy.member.domain.dto.MemberJoinRequestDto;
import saphy.saphy.member.service.MemberJoinService;

@RestController
@RequiredArgsConstructor
@RequestMapping // api 결정되면 수정 필요
public class MemberJoinController {

    private final MemberJoinService memberJoinService;

    @PostMapping("/join")
    public ApiResponse<Member> join(@Validated @RequestBody MemberJoinRequestDto memberJoinRequest, Errors errors) {
        validateRequest(errors);
        memberJoinService.join(memberJoinRequest);
        return new ApiResponse<>(ErrorCode.REQUEST_OK);
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
