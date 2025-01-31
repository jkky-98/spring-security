package com.piehealthcare.authserver.repository;

import com.piehealthcare.authserver.domain.Member;
import com.piehealthcare.authserver.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    boolean existsByMemberAndRefreshToken(Member member, String refreshToken);
    Optional<RefreshToken> findByMemberAndRefreshToken(Member member, String refreshToken);
}
