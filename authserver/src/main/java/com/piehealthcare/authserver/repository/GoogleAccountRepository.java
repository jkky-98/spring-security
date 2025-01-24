package com.piehealthcare.authserver.repository;

import com.piehealthcare.authserver.domain.GoogleAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GoogleAccountRepository extends JpaRepository<GoogleAccount, Long> {
    Optional<GoogleAccount> findByEmail(String email);
}
