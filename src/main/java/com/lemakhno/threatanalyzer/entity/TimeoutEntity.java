package com.lemakhno.threatanalyzer.entity;

/*
import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
*/

/*
@Entity
@Table(name = "timeouts")
public class TimeoutEntity {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "host", unique = true, nullable = false)
    private String host;

    @Column(name = "count", nullable = false)
    private Integer count;

    private LocalDateTime lasTime;

    public TimeoutEntity() {}

    public TimeoutEntity(String host, Integer count) {
        this.host = host;
        this.count = count;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }

    @Override
    public String toString() {
        return "TimeoutEntity [id=" + id + ", host=" + host + ", count=" + count + "]";
    }
}
*/
