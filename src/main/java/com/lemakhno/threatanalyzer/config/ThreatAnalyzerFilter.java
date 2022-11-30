package com.lemakhno.threatanalyzer.config;

import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.PATCH;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.lemakhno.threatanalyzer.analyzer.ThreatAnalyzer;
import com.lemakhno.threatanalyzer.model.RequestDetails;
import com.lemakhno.threatanalyzer.security.servlet.wrapper.CachedBodyHttpServletRequest;

@Component
public class ThreatAnalyzerFilter extends OncePerRequestFilter {

    @Autowired
    private ThreatAnalyzer threatAnalyzer;

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.info("-- Threat analysis --");

        CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
        
        RequestDetails requestDetails = new RequestDetails()
            .setEndpoint(request.getContextPath())
            .setMethod(request.getMethod())
            .setSourceHost(request.getHeader("Host").isEmpty() ? "Caller address unavailable" : request.getHeader("Host"));
        
        logger.info("Request from host: {}, endpoint: {}, method: {}",
            requestDetails.getSourceHost(), requestDetails.getEndpoint(), requestDetails.getMethod());
        
        boolean isBodyContainedMethod = List.of(POST.name(), PUT.name(), PATCH.name(), DELETE.name()).contains(request.getMethod());
        boolean containsBody = isBodyContainedMethod && !List.of(-1, 0).contains(request.getContentLength());
        
        threatAnalyzer.corsCheck(requestDetails);
        
        logger.info("-- Threat analysis end --");
        filterChain.doFilter(cachedRequest, response);
    }
}
