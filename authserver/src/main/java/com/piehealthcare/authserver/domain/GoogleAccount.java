package com.piehealthcare.authserver.domain;

import jakarta.persistence.*;
import lombok.*;
import org.antlr.v4.runtime.misc.NotNull;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA 기본 생성자
@AllArgsConstructor(access = AccessLevel.PRIVATE) // 빌더와 함께 사용할 모든 필드 생성자
public class GoogleAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "google_id")
    private Long id;

    @NotNull
    private String sub;

    @Column(unique = true, nullable = false)
    private String email; // 사용자의 이메일 주소

    private String name; // 사용자의 이름 (optional)

    private String picture; // 사용자의 프로필 사진 URL

    private boolean emailVerified; // 이메일 인증 여부

    private String hd; // GSuite 도메인 (optional, 예: "ajou.ac.kr")

    // Member와의 연관 관계 설정
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;
}