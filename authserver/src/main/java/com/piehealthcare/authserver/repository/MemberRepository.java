package com.piehealthcare.authserver.repository;

import com.piehealthcare.authserver.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    @Query("SELECT m FROM Member m JOIN m.googleAccount g WHERE g.sub = :sub")
    Optional<Member> findBySub(@Param("sub") String sub);
    Optional<Member> findByIdentifier(String identifier);
}
