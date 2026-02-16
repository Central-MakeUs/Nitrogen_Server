package com.nitrogen.domain.user.repository;

import com.nitrogen.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    @Query("SELECT u FROM User u WHERE u.socialId = :socialId AND u.socialId IS NOT NULL")
    Optional<User> findBySocialId(@Param("socialId") String socialId);

    @Query("SELECT u FROM User u WHERE u.appleSub = :appleSub AND u.appleSub IS NOT NULL")
    Optional<User> findByAppleSub(@Param("appleSub") String appleSub);
}
