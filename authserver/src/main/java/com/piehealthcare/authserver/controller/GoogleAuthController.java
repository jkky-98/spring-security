package com.piehealthcare.authserver.controller;

import com.piehealthcare.authserver.service.GoogleAccountService;
import com.piehealthcare.authserver.service.GoogleIdTokenParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

// Google 로그인 컨트롤러
@RestController
@RequestMapping("/login/google")
@RequiredArgsConstructor
@Slf4j
public class GoogleAuthController {

    private final GoogleAccountService googleAccountService;

    @PostMapping("")
    public ResponseEntity<?> authenticate(@RequestHeader("Authorization") String authorizationHeader) {
        log.info("Authenticating token : {}", authorizationHeader);
        // "Bearer " 접두사 제거
        String googleIdToken = authorizationHeader.replace("Bearer ", "").trim();
        // 구글 토큰 검증
        Map<String, Object> googleProfile = GoogleIdTokenParser.parseIdToken(googleIdToken);
        String jwtToken = googleAccountService.authenticateAndGenerateToken(googleProfile);
        log.info("JWT token : {}", jwtToken);

        return ResponseEntity.ofNullable(jwtToken);
    }
}
