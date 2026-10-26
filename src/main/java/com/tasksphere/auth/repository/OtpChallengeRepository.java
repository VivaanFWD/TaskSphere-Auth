package com.tasksphere.auth.repository;

import com.tasksphere.auth.domain.OtpChallenge;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OtpChallengeRepository extends JpaRepository<OtpChallenge, UUID> {
    Optional<OtpChallenge> findByPurposeAndIdentifierAndUsedAtIsNull(String purpose, String identifier);
    Optional<OtpChallenge> findTopByPurposeAndIdentifierOrderByCreatedAtDesc(String purpose, String identifier);
}
