package com.lemakhno.threatanalyzer.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.lemakhno.threatanalyzer.entity.AppUserEntity;

@Repository
public interface AppUserRepository extends JpaRepository<AppUserEntity, Long> {
    
    public AppUserEntity findByUsername(String username);
}
