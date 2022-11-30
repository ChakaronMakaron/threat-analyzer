package com.lemakhno.threatanalyzer.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class AppSecurityFilterChain {

    @Autowired
    private ThreatAnalyzerFilter threatAnalyzerFilter;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
            .csrf()
            .ignoringAntMatchers("/login")
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

        //httpSecurity.csrf().disable();
        
        httpSecurity
            .authorizeRequests()
                .antMatchers("/login")
                    .permitAll()
                .anyRequest()
                    .authenticated();

        httpSecurity
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.ALWAYS);

        httpSecurity
            .addFilterBefore(threatAnalyzerFilter, SecurityContextHolderFilter.class);

        return httpSecurity.build();
    }
}
