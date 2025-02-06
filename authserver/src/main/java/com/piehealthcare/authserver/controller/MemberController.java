package com.piehealthcare.authserver.controller;

import com.piehealthcare.authserver.dto.ResponseDto;
import com.piehealthcare.authserver.service.JwtService;
import com.piehealthcare.authserver.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class MemberController {

    private final MemberService memberService;
    private final JwtService jwtService;

    @GetMapping("navigation/userinfo")
    public ResponseEntity<?> getUserInfo(
            @RequestHeader("Authorization") String accessToken
    ) {
        log.info("Get user information");
        log.info("Access token: {}", accessToken);
        String token = accessToken.substring(7);
        String userIdentifier = jwtService.extractUsername(token);
        log.info("User identifier: {}", userIdentifier);
        ResponseDto<?> returnDto = memberService.findMemberNavigationInfo(userIdentifier);
        log.info("Return DTO: {}", returnDto);
        return ResponseEntity.ok(returnDto);
    }
}
