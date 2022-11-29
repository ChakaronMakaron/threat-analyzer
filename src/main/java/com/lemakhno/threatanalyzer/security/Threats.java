package com.lemakhno.threatanalyzer.security;

public enum Threats {

    SQL_INJECTION("SQL injection attempt"),
    CSRF("CSRF violation"),
    CORS("CORS policy violation"),
    BRUTE_FORCE("Brute force attempt");
    
    private String typeDesctiption;

    Threats(String description) {
        this.typeDesctiption = description;
    }

    public String getTypeDescription() {
        return typeDesctiption;
    }
}
