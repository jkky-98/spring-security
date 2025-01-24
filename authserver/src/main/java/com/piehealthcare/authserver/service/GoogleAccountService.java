package com.piehealthcare.authserver.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.piehealthcare.authserver.domain.GoogleAccount;
import com.piehealthcare.authserver.domain.Member;
import com.piehealthcare.authserver.domain.Role;
import com.piehealthcare.authserver.repository.GoogleAccountRepository;
import com.piehealthcare.authserver.repository.MemberRepository;
import com.piehealthcare.authserver.securityutil.JwtGenerator;
import com.piehealthcare.authserver.securityutil.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoogleAccountService {

    private final GoogleAccountRepository googleAccountRepository;
    private final JwtEncoder jwtEncoder;
    private final MemberRepository memberRepository;
    private final JwtGenerator jwtGenerator;

    @Value("${jwt.secret-key}")
    private String jwtSecret;
    @Value("${jwt.access-expiration}")
    private Long jwtExpiration;

    public String authenticateAndGenerateToken(Map<String, Object> googleProfile) {

        // Google 사용자 정보 추출
        String sub = googleProfile.get("sub").toString();
        String email = googleProfile.get("email").toString();
        Boolean emailVerified = Boolean.parseBoolean(googleProfile.get("email_verified").toString());
        String name = googleProfile.get("name").toString();

        // 내부 DB에서 유저 검색
        Member member = memberRepository.findBySub(sub)
                .orElseGet(() -> {
                    // 내부 DB에 유저가 없을 경우 회원가입
                    Member newMember = Member.builder()
                            .role(Role.USER)
                            .identifier(UUID.randomUUID().toString())
                            .build();

                    GoogleAccount newGoogleAccount = GoogleAccount.builder()
                            .member(newMember)
                            .sub(sub)
                            .email(email)
                            .emailVerified(emailVerified)
                            .name(name)
                            .build();

                    // 데이터베이스에 저장
                    memberRepository.save(newMember);
                    googleAccountRepository.save(newGoogleAccount);

                    return newMember;
                });
        return jwtGenerator.generateAccessToken(
                JwtUtils.getKeyFromSecret(jwtSecret), // Key 변환
                jwtExpiration,
                member
        );
    }
}
