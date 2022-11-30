package com.lemakhno.threatanalyzer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AppSecurityFilterChain {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.csrf().disable();
        
        httpSecurity
            .authorizeRequests()
                .antMatchers("/login")
                    .permitAll()
                .anyRequest()
                    .authenticated();

        httpSecurity
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.ALWAYS);

        return httpSecurity.build();
    }
}
