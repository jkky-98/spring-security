package com.piehealthcare.authserver.service;

import com.piehealthcare.authserver.domain.Member;
import com.piehealthcare.authserver.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        // Identifier를 기준으로 사용자 조회
        Member member = memberRepository.findByIdentifier(identifier)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with identifier: " + identifier));

        return new org.springframework.security.core.userdetails.User(
                member.getIdentifier(),
                "",
                List.of(new SimpleGrantedAuthority(member.getRole().getKey()))
        );
    }
}
