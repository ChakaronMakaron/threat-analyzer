package com.lemakhno.threatanalyzer.model;

import javax.servlet.http.Cookie;

public class RequestDetails {
    
    private String sourceHost;
    private String endpoint;
    private String method;
    private String csrfHeader;
    private Cookie[] cookies;
    
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

    public Cookie[] getCookies() {
        return cookies;
    }

    public RequestDetails setCookies(Cookie[] cookies) {
        this.cookies = cookies;
        return this;
    }

    public String getCsrfHeader() {
        return csrfHeader;
    }

    public RequestDetails setCsrfHeader(String csrfHeader) {
        this.csrfHeader = csrfHeader;
        return this;
    }

    @Override
    public String toString() {
        return "RequestDetails [endpoint=" + endpoint + ", method=" + method + "]";
    }
}
