package com.lemakhno.threatanalyzer.analyzer;

import static java.lang.String.format;
import static org.apache.commons.lang3.StringUtils.containsIgnoreCase;

import java.time.LocalDateTime;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lemakhno.threatanalyzer.config.Constants;
import com.lemakhno.threatanalyzer.config.Threats;
import com.lemakhno.threatanalyzer.entity.ThreatEntity;
import com.lemakhno.threatanalyzer.model.RequestDetails;
import com.lemakhno.threatanalyzer.repository.ThreatRepository;
import com.lemakhno.threatanalyzer.utils.AppUtils;

@Component
public class ThreatAnalyzer {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private ThreatRepository threatRepository;
    
    public void corsCheck(RequestDetails requestDetails) {
        logger.info("CORS policy violation check");
        if (!Constants.ALLOWED_HOSTS.contains(requestDetails.getSourceHost())) {
            logger.info("CORS policy violation");
            ThreatEntity threatEntity = new ThreatEntity()
                .setType(Threats.CORS.getTypeDescription())
                .setSourceHost(requestDetails.getSourceHost())
                .setDateTime(LocalDateTime.now())
                .setDetails("Endpoint: " + requestDetails.getEndpoint() + ", method: " + requestDetails.getMethod());
            ThreatEntity savedThreatEntity = threatRepository.save(threatEntity);
            logger.info("CORS violation threat record id: {}", savedThreatEntity.getId());
        }
    }

    public void sqlInjectionCheck(RequestDetails requestDetails, Object object) {
        Map<String, String> body = AppUtils.objectToMap(object);
        logger.info("SQL injection check");
        if (!body.isEmpty()) {
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
                    .setSourceHost(requestDetails.getSourceHost())
                    .setDateTime(LocalDateTime.now())
                    .setDetails(keywordsFound.toString());
                ThreatEntity savedThreatEntity = threatRepository.save(threatEntity);
                logger.info("SQL injection threat record id: {}", savedThreatEntity.getId());
            }
        }
    }
}
