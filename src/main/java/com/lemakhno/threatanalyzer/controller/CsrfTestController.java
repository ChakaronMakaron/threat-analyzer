package com.lemakhno.threatanalyzer.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CsrfTestController {
    
    @PostMapping("/csrf")
    public String csrfTest() {
        return "CSRF PASSED";
    }
}
