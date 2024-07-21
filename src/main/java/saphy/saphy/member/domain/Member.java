package saphy.saphy.member.domain;

import jakarta.persistence.*;
import lombok.*;
import saphy.saphy.bookmark.domain.Bookmark;

import java.util.List;

@Entity
@Builder
@Getter @Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Table(name = "members")
public class Member {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String loginId;

    @Column(nullable = false)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SocialType socialType;

    @Column(nullable = false)
    private String name;

    private String address;

    @Column(nullable = false)
    private String phoneNumber;

    @Column
    private String email;

    @Column(nullable = false)
    private Boolean isAdmin;

    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Bookmark> bookmarks;
}