package com.piehealthcare.authserver.securityutil;

import com.piehealthcare.authserver.domain.Member;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtGenerator {

    public String generateAccessToken(final Key ACCESS_SECRET,
                                      final Long ACCESS_EXPIRATION,
                                      Member member) {

        Long now = System.currentTimeMillis();

        return Jwts.builder()
                .setHeader(createHeader())
                .setClaims(createClaims(member))
                .setSubject(member.getIdentifier())
                .setExpiration(new Date(now + ACCESS_EXPIRATION))
                .signWith(ACCESS_SECRET, SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(final Key REFRESH_SECRET,
                                       final long REFRESH_EXPIRATION,
                                       Member member) {
        Long now = System.currentTimeMillis();

        return Jwts.builder()
                .setHeader(createHeader())
                .setSubject(member.getIdentifier())
                .setExpiration(new Date(now + REFRESH_EXPIRATION))
                .signWith(REFRESH_SECRET, SignatureAlgorithm.HS256)
                .compact();
    }

    private Map<String, Object> createHeader() {
        Map<String, Object> header = new HashMap<>();
        header.put("typ", "JWT");
        header.put("alg", "HS256");
        return header;
    }

    private Map<String, Object> createClaims(Member member) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("Identifier", member.getIdentifier());
        claims.put("Role", member.getRole());
        return claims;
    }
}
