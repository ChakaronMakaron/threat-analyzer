package com.lemakhno.threatanalyzer.security;

import static com.lemakhno.threatanalyzer.utils.AppUtils.formDataToMap;
import static java.lang.String.format;
import static java.util.Objects.isNull;
import static org.apache.commons.lang3.StringUtils.containsIgnoreCase;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.PATCH;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.lemakhno.threatanalyzer.entity.ThreatEntity;
import com.lemakhno.threatanalyzer.repository.ThreatRepository;

@Component
public class ThreatAnalyzerFilter extends OncePerRequestFilter {

    @Autowired
    private ThreatRepository threatRepository;

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.info("-- Threat analysis --");

        String sourceHost = request.getHeader("Host");
        String endpoint = request.getContextPath().isBlank() ? "/" : request.getContextPath();
        logger.info("Request from host: {}, endpoint: {}, method: {}", sourceHost, endpoint, request.getMethod());
        
        boolean isBodyContainedMethod = List.of(POST.name(), PUT.name(), PATCH.name(), DELETE.name()).contains(request.getMethod());
        boolean containsBody = isBodyContainedMethod && !List.of(-1, 0).contains(request.getContentLength());
        
        Map<String, String> body = formDataToMap(request.getReader());

        if (Constants.IS_CSRF_ENABLED && isBodyContainedMethod) {
            logger.info("CSRF violation check");
            if (isNull(body.get("_csrf"))) {
                logger.info("CSRF violation");
                ThreatEntity threatEntity = new ThreatEntity()
                    .setType(Threats.CSRF.getTypeDescription())
                    .setSourceHost(sourceHost)
                    .setDateTime(LocalDateTime.now())
                    .setDetails("Endpoint: " + endpoint + ", method: " + request.getMethod());
                ThreatEntity savedThreatEntity = threatRepository.save(threatEntity);
                logger.info("CSRF violation threat record id: {}", savedThreatEntity.getId());
            }
        }
        
        logger.info("CORS policy violation check");
        if (!Constants.ALLOWED_HOSTS.contains(sourceHost)) {
            logger.info("CORS policy violation");
            ThreatEntity threatEntity = new ThreatEntity()
                .setType(Threats.CORS.getTypeDescription())
                .setSourceHost(sourceHost)
                .setDateTime(LocalDateTime.now())
                .setDetails("Endpoint: " + endpoint + ", method: " + request.getMethod());
            ThreatEntity savedThreatEntity = threatRepository.save(threatEntity);
            logger.info("CORS violation threat record id: {}", savedThreatEntity.getId());
        }

        logger.info("SQL injection check");
        if (containsBody) {
            logger.info("Body: {}", body);
            StringBuilder keywordsFound = new StringBuilder();
            Constants.SQL_KEYWORDS.forEach(keyword -> {
                body.forEach((field, fieldValue) -> {
                    if (containsIgnoreCase(fieldValue, keyword)) {
                        keywordsFound.append(format("[%s: %s]", field, keyword));
                    }
                });
            });

            if (!keywordsFound.toString().isEmpty()) {
                ThreatEntity threatEntity = new ThreatEntity()
                    .setType(Threats.SQL_INJECTION.getTypeDescription())
                    .setSourceHost(sourceHost)
                    .setDateTime(LocalDateTime.now())
                    .setDetails(keywordsFound.toString());
                ThreatEntity savedThreatEntity = threatRepository.save(threatEntity);
                logger.info("SQL injection threat record id: {}", savedThreatEntity.getId());
            }
        }
        
        logger.info("-- Threat analysis end --");
        filterChain.doFilter(request, response);
    }
}
