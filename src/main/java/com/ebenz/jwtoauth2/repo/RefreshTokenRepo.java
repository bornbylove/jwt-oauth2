package com.ebenz.jwtoauth2.repo;

import com.ebenz.jwtoauth2.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.web.server.WebFilter;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshTokenEntity, Long> {
    Optional<RefreshTokenEntity> findByRefreshToken(String refreshToken);

    // Will be implemeted later to logout all users
    @Query(value = "SELECT rt.* FROM REFRESH_TOKENS rt " +
            "INNER JOIN USER_DETAILS ud ON rt.user_id = ud.id " +
            "WHERE ud.EMAIL = :userEmail and rt.revoked = false ", nativeQuery = true)
    List<RefreshTokenEntity> findAllRefreshTokenByUserEmailId(String userEmail);
}

