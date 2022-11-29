package com.lemakhno.threatanalyzer.security;

import java.util.List;

public class Constants {
    
    public static final List<String> ALLOWED_HOSTS = List.of("localhost:8080", "http://front.end");
    public static final boolean IS_CSRF_ENABLED = true;
    public static final List<String> SQL_KEYWORDS = List.of(
        "ADD", "CONSTRAINT", "ALL", "ALTER", "COLUMN", "TABLE",
        "AND", "ANY", "AS", "ASC", "BACKUP", "DATABASE", "BETWEEN",
        "CASE", "CHECK", "CREATE", "INDEX", "OR", "REPLACE", "VIEW",
        "PROCEDURE", "UNIQUE", "DEFAULT", "DELETE", "DESC", "DISTINCT",
        "DROP", "EXEC", "EXISTS", "FOREIGN", "KEY", "FROM", "FULL",
        "OUTER", "JOIN", "GROUP", "BY", "HAVING", "IN", "INNER", "INTO",
        "INSERT", "SELECT", "IS", "NULL", "NOT", "LEFT", "RIGHT", "LIKE",
        "LIMIT", "OR", "BY", "ORDER","PRIMARY", "ROWNUM", "TOP", "SET",
        "TRUNCATE", "UNION", "UPDATE", "VALUES", "WHERE"
    );
}
