package com.ebenz.jwtoauth2.repo;

import com.ebenz.jwtoauth2.entity.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserInfoRepo extends JpaRepository<UserInfoEntity,Long> {
    Optional<UserInfoEntity> findByEmailId(String emailId);
    Optional<UserInfoEntity> findByUserName(String usernameId);
}
