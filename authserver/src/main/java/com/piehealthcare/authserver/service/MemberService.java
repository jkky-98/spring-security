package com.piehealthcare.authserver.service;

import com.piehealthcare.authserver.domain.GoogleAccount;
import com.piehealthcare.authserver.domain.Member;
import com.piehealthcare.authserver.dto.NavigationUserInfoDto;
import com.piehealthcare.authserver.dto.ResponseDto;
import com.piehealthcare.authserver.repository.MemberRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService {

    private final MemberRepository memberRepository;

    public ResponseDto<?> findMemberNavigationInfo(String memberIdentifier) {
        Member member = memberRepository.findByIdentifier(memberIdentifier).orElseThrow(() -> new EntityNotFoundException("Member not found"));
        // 현재는 구글의 경우만
        GoogleAccount googleAccount = member.getGoogleAccount();

        NavigationUserInfoDto dto = new NavigationUserInfoDto();
        dto.setEmail(googleAccount.getEmail());
        dto.setUsername(googleAccount.getName());

        log.info("dto: {}", dto);

        return new ResponseDto(
                HttpStatus.CREATED.value(),
                "Navigation UserInfo 반환 성공",
                dto
                );
    }
}
