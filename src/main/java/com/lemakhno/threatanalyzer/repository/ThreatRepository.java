package com.lemakhno.threatanalyzer.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.lemakhno.threatanalyzer.entity.ThreatEntity;

public interface ThreatRepository extends JpaRepository<ThreatEntity, Long> {}
