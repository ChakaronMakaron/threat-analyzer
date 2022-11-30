package com.lemakhno.threatanalyzer.config;

import static com.lemakhno.threatanalyzer.utils.AppUtils.getRequestDetails;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lemakhno.threatanalyzer.analyzer.ThreatAnalyzer;
import com.lemakhno.threatanalyzer.model.AuthenticationRequest;
import com.lemakhno.threatanalyzer.model.RequestDetails;

@Component
public class AppAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ThreatAnalyzer threatAnalyzer;

    public AppAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.setAuthenticationManager(authenticationManager);
        this.setFilterProcessesUrl("/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        logger.info("-- Authentication attempt --");

        RequestDetails requestDetails = getRequestDetails(request);
        logger.info("Request details: {}", requestDetails);

        try {

            AuthenticationRequest authenticationRequest = objectMapper.readValue(request.getReader(), AuthenticationRequest.class);

            logger.info("Authentication body: {}", authenticationRequest);

            threatAnalyzer.corsCheck(requestDetails);
            threatAnalyzer.sqlInjectionCheck(requestDetails, authenticationRequest);

            UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword());
            
            return getAuthenticationManager().authenticate(authenticationToken);

        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {

        logger.info("Failed authentication, cause: " + failed.getMessage());

        Map<String, String> responseBody = Map.of("message", "Bad credentials");

        response.setContentType("application/json");
        response.setStatus(401);

        objectMapper.writeValue(response.getOutputStream(), responseBody);
    }
}
