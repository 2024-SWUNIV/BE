package saphy.saphy.auth.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import saphy.saphy.member.domain.Member;

import java.util.Collection;

public class CustomMemberDetails implements UserDetails {

    // 스프링 시큐리티 필터 검증에 사용되는 객체
    private final Member member;

    public CustomMemberDetails(Member member) {

        this.member = member;
    }

    public Member getMember() {

        return member;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        return null;
    }

    @Override
    public String getPassword() {

        return member.getPassword();
    }

    @Override
    public String getUsername() {

        return member.getLoginId();
    }
}
