package com.piehealthcare.authserver.service;

import com.piehealthcare.authserver.domain.Member;
import com.piehealthcare.authserver.domain.RefreshToken;
import com.piehealthcare.authserver.exception.JwtExpiredException;
import com.piehealthcare.authserver.exception.JwtRefreshClientException;
import com.piehealthcare.authserver.repository.MemberRepository;
import com.piehealthcare.authserver.repository.RefreshTokenRepository;
import com.piehealthcare.authserver.securityutil.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final MemberRepository memberRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.secret-key}")
    private String SECRET_KEY;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractRole(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("Role", String.class); // 단일 Role(String) 반환
    }

    // 토큰 검증
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    // 리프레시 토큰 검증
    @Transactional(readOnly = true)
    public void isRefreshTokenValid(String refreshToken, String accessToken) {
        if (refreshToken == null) {
            throw new JwtRefreshClientException("Refresh token is null");
        }

        if (!isSameExpiredAccessTokenAndRefreshToken(refreshToken, accessToken)) {
            throw new JwtRefreshClientException("is not same expired access token");
        }

        if (isTokenExpired(refreshToken)) {
            throw new JwtExpiredException("refresh token expired", refreshToken);
        }

        String identifier = extractUsername(refreshToken);
        Member member = memberRepository.findByIdentifier(identifier).orElseThrow(() -> new EntityNotFoundException("member not found"));

        if (!refreshTokenRepository.existsByMemberAndRefreshToken(member, refreshToken)) {
            throw new JwtRefreshClientException("refresh token not found in DB");
        }

    }

    @Transactional
    public void updateRefreshToken(String oldRefreshToken, String newRefreshToken, Member member) {
        RefreshToken oldRefresh = refreshTokenRepository.findByMemberAndRefreshToken(member, oldRefreshToken).orElseThrow(() -> new EntityNotFoundException("refresh token not found"));

        refreshTokenRepository.delete(
                oldRefresh
        );

        refreshTokenRepository.save(
                RefreshToken.of(newRefreshToken, member)
        );

    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(JwtUtils.getKeyFromSecret(SECRET_KEY))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isSameExpiredAccessTokenAndRefreshToken(String expiredAccessToken, String refreshToken) {
        String usernameExpiredAccess = extractUsername(expiredAccessToken);
        String usernameRefresh = extractUsername(refreshToken);

        return usernameExpiredAccess.equals(usernameRefresh);
    }
}
