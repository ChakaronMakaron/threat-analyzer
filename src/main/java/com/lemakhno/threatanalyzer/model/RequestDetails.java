package com.lemakhno.threatanalyzer.model;

public class RequestDetails {
    
    private String sourceHost;
    private String endpoint;
    private String method;
    
    public String getEndpoint() {
        return endpoint;
    }

    public RequestDetails setEndpoint(String endpoint) {
        this.endpoint = endpoint;
        return this;
    }

    public String getMethod() {
        return method;
    }

    public RequestDetails setMethod(String method) {
        this.method = method;
        return this;
    }

    public String getSourceHost() {
        return sourceHost;
    }

    public RequestDetails setSourceHost(String sourceHost) {
        this.sourceHost = sourceHost;
        return this;
    }

    @Override
    public String toString() {
        return "RequestDetails [endpoint=" + endpoint + ", method=" + method + "]";
    }
}
