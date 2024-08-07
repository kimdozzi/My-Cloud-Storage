package com.example.deploy.security.jwt.repository;

import com.example.deploy.security.jwt.domain.Refresh;
import org.springframework.data.repository.CrudRepository;

public interface RefreshRepository extends CrudRepository<Refresh, Long> {

}
