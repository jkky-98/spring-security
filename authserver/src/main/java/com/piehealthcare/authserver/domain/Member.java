package com.piehealthcare.authserver.domain;

import com.piehealthcare.authserver.domain.base.BaseTimeEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;


@Entity
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA 기본 생성자
@AllArgsConstructor(access = AccessLevel.PRIVATE) // 빌더와 함께 사용할 모든 필드 생성자
public class Member extends BaseTimeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    @Column(name = "identifier", unique = true, nullable = false, updatable = false)
    private String identifier;

    @Enumerated(EnumType.STRING) // Enum을 문자열로 저장 (예: "ADMIN", "USER")
    @Column(name = "role", nullable = false)
    private Role role;

    @Builder.Default
    @OneToOne(mappedBy = "member", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    private GoogleAccount googleAccount = null;

    @Builder.Default
    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<RefreshToken> refreshTokens = new ArrayList<>();

    public void updateGoogleAccount(GoogleAccount googleAccount) {
        this.googleAccount = googleAccount;
        googleAccount.setMember(this);
    }
}
