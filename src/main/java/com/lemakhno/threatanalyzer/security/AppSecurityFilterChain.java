package com.lemakhno.threatanalyzer.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
public class AppSecurityFilterChain {

    @Autowired
    private OncePerRequestFilter threatAnalyzerFilter;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
            .formLogin();

        httpSecurity
            .csrf()
            .disable();

        /*
        httpSecurity
            .csrf()
                .ignoringAntMatchers("/api/login")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        */
        
        httpSecurity
            .authorizeRequests()
                .anyRequest()
                .authenticated();

        
        httpSecurity
        .addFilterBefore(threatAnalyzerFilter, UsernamePasswordAuthenticationFilter.class); // Or UsernamePasswordAuthenticationFilter

        return httpSecurity.build();
    }
}
