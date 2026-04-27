package com.dev.security.repository;

import com.dev.security.model.UserAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAuthRepository extends  JpaRepository<UserAuth, Integer> {

    Optional<UserAuth> findByEmail(String email);
}
