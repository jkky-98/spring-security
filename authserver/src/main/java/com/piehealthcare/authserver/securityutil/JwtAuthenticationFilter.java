package com.piehealthcare.authserver.securityutil;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.piehealthcare.authserver.domain.Member;
import com.piehealthcare.authserver.dto.JwtResponseDto;
import com.piehealthcare.authserver.dto.ResponseDto;
import com.piehealthcare.authserver.exception.JwtExpiredException;
import com.piehealthcare.authserver.exception.JwtRefreshClientException;
import com.piehealthcare.authserver.repository.MemberRepository;
import com.piehealthcare.authserver.repository.RefreshTokenRepository;
import com.piehealthcare.authserver.service.CustomUserDetailsService;
import com.piehealthcare.authserver.service.JwtService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JwtGenerator jwtGenerator;
    private final MemberRepository memberRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.secret-key}")
    private String jwtSecret;
    @Value("${jwt.access-expiration}")
    private Long jwtExpiration;
    @Value("${jwt.refresh-expiration}")
    private Long refreshExpiration;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // 제외할 경로 목록
        List<String> excludedPaths = Arrays.asList(
                "/login/google",
                "/error"
        );

        // 경로가 제외 목록에 포함되어 있으면 필터링 제외
        return excludedPaths.stream().anyMatch(path::startsWith);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            // 기존 JWT 검증 로직
            String authHeader = request.getHeader("Authorization");

            // Bearer 형식 확인
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                // 토큰 만료 확인
                if (jwtService.isTokenExpired(token)) {
                    throw new JwtExpiredException("JWT token is expired", token);
                }

                // 토큰이 유효한 경우, username과 roles만 추출하여 SecurityContext 설정
                String username = jwtService.extractUsername(token);
                String role = jwtService.extractRole(token); // 클레임에서 역할(role) 정보 추출

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    // 단일 Role을 SimpleGrantedAuthority로 변환
                    GrantedAuthority authority = new SimpleGrantedAuthority(role);

                    // SecurityContext에 저장
                    var authToken = new UsernamePasswordAuthenticationToken(username, null, List.of(authority));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

            filterChain.doFilter(request, response);
        } catch (JwtExpiredException e) {
            String expiredToken = e.getExpiredToken();
            handleRefreshToken(request, response, filterChain, expiredToken);
        }
    }

    private void handleRefreshToken(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, String expiredAccessToken) throws IOException {
        ContentCachingRequestWrapper cachingRequest = new ContentCachingRequestWrapper(request);
        String refreshToken = extractRefreshTokenFromHeader(cachingRequest);

        try {
            jwtService.isRefreshTokenValid(expiredAccessToken, refreshToken);

            Member member = memberRepository.findBySub(refreshToken).orElseThrow(() -> new EntityNotFoundException("User not found"));

            String newAccessToken = jwtGenerator.generateAccessToken(
                    JwtUtils.getKeyFromSecret(jwtSecret), // Key 변환
                    jwtExpiration,
                    member);

            String newRefreshToken = jwtGenerator.generateRefreshToken(
                    JwtUtils.getKeyFromSecret(jwtSecret),
                    refreshExpiration,
                    member
            );

            jwtService.updateRefreshToken(refreshToken, newRefreshToken, member);

            JwtResponseDto jwtResponseDto = new JwtResponseDto();
            jwtResponseDto.setAccessToken(newAccessToken);
            jwtResponseDto.setRefreshToken(newRefreshToken);

            ResponseDto responseDto = new ResponseDto(
                    HttpStatus.CREATED.value(),
                    "AccessToken 만료, Refresh 토큰으로 재 발급",
                    jwtResponseDto
            );

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(responseDto));

        } catch (JwtExpiredException e) {
            ResponseDto responseDto = new ResponseDto(
                    HttpStatus.UNAUTHORIZED.value(),
                    "AcessToken 만료, Refresh 토큰 만료 : 재 로그인 필요",
                    null
            );

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(responseDto));

        } catch (JwtRefreshClientException e) {
            ResponseDto responseDto = new ResponseDto(
                    HttpStatus.UNAUTHORIZED.value(),
                    e.getMessage(),
                    null
            );

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(responseDto));
        }
    }

    private String extractRefreshTokenFromHeader(HttpServletRequest request) {
        // "X-Refresh-Token" 헤더의 값을 읽어옵니다.
        String refreshToken = request.getHeader("X-Refresh-Token");
        return (refreshToken != null && !refreshToken.isEmpty()) ? refreshToken.trim() : null;
    }
}
