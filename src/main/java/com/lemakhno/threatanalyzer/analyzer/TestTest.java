package com.lemakhno.threatanalyzer.analyzer;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

public class TestTest {
    
    public static void main(String[] args) throws InterruptedException {

        // 2022-12-01T10:37:55.307249600, 2022-12-01T10:37:59.479618500
        
        LocalDateTime localDateTime1 = LocalDateTime.parse("2022-12-01T10:37:55.307249600");

        LocalDateTime localDateTime2 = LocalDateTime.parse("2022-12-01T10:37:59.479618500");

        System.out.println(ChronoUnit.SECONDS.between(localDateTime1, localDateTime2));
    }
}
