package com.example.deploy.security.jwt.repository;

import com.example.deploy.security.jwt.domain.Refresh;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface RefreshRepository extends JpaRepository<Refresh, Long> {

}
