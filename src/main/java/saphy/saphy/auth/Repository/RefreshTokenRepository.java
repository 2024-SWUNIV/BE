package saphy.saphy.auth.Repository;

import org.springframework.data.repository.CrudRepository;
import saphy.saphy.auth.domain.RefreshToken;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken,String> {
    // 페이징, 정렬 필요 없이 기본 CRUD만 사용 - Crud Repository 상속이 적합
    RefreshToken findByToken(String token);
}
