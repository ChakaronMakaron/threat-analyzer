package com.lemakhno.threatanalyzer.entity;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "threats")
public class ThreatEntity {
    
    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "source_host", nullable = false)
    private String sourceHost;

    @Column(name = "type", nullable = false)
    private String type;

    @Column(name = "date_time", nullable = false)
    private LocalDateTime dateTime;

    @Column(name = "details")
    private String details;

    public ThreatEntity() {}

    public ThreatEntity(String sourceHost, String type, LocalDateTime dateTime, String details) {
        this.sourceHost = sourceHost;
        this.type = type;
        this.dateTime = dateTime;
        this.details = details;
    }

    public Long getId() {
        return id;
    }

    public ThreatEntity setId(Long id) {
        this.id = id;
        return this;
    }

    public String getSourceHost() {
        return sourceHost;
    }

    public ThreatEntity setSourceHost(String sourceHost) {
        this.sourceHost = sourceHost;
        return this;
    }

    public String getType() {
        return type;
    }

    public ThreatEntity setType(String type) {
        this.type = type;
        return this;
    }

    public LocalDateTime getDateTime() {
        return dateTime;
    }

    public ThreatEntity setDateTime(LocalDateTime dateTime) {
        this.dateTime = dateTime;
        return this;
    }

    public String getDetails() {
        return details;
    }

    public ThreatEntity setDetails(String details) {
        this.details = details;
        return this;
    }

    @Override
    public String toString() {
        return "ThreatEntity [id=" + id + ", sourceHost=" + sourceHost + ", type=" + type + ", dateTime=" + dateTime
                + ", details=" + details + "]";
    }
}
