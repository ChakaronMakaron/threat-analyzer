package com.lemakhno.threatanalyzer.analyzer;

import java.time.LocalDateTime;

public class HostTimeoutDetails {
    
    private String host;
    private LocalDateTime lastRequestTime;
    private int count;

    public String getHost() {
        return host;
    }

    public HostTimeoutDetails setHost(String host) {
        this.host = host;
        return this;
    }

    public LocalDateTime getLastRequestTime() {
        return lastRequestTime;
    }

    public HostTimeoutDetails setLastRequestTime(LocalDateTime lastRequestTime) {
        this.lastRequestTime = lastRequestTime;
        return this;
    }

    public int getCount() {
        return count;
    }
    
    public HostTimeoutDetails setCount(int count) {
        this.count = count;
        return this;
    }

    public HostTimeoutDetails() {}

    public HostTimeoutDetails(String host, LocalDateTime lastRequestTime, int count) {
        this.host = host;
        this.lastRequestTime = lastRequestTime;
        this.count = count;
    }

    @Override
    public String toString() {
        return "RequestTimeoutDetails [host=" + host + ", lastRequestTime=" + lastRequestTime + ", count=" + count
                + "]";
    }
}
