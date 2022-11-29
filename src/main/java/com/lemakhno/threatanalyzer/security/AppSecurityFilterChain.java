package com.lemakhno.threatanalyzer.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class AppSecurityFilterChain {

    @Autowired
    private ThreatAnalyzerFilter threatAnalyzerFilter;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        
        httpSecurity
            .formLogin();
        
        httpSecurity
            .authorizeRequests()
                .antMatchers("/css/**", "/js/**", "/images/**")
                .permitAll();
        /*
        httpSecurity
            .csrf()
                .ignoringAntMatchers("/api/login")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        */

        // httpSecurity.csrf().disable();
        
        httpSecurity
            .authorizeRequests()
                .anyRequest()
                .authenticated();

        httpSecurity
            .addFilterAfter(threatAnalyzerFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}
