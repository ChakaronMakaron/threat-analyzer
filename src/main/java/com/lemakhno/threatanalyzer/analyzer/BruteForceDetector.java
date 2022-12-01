package com.lemakhno.threatanalyzer.analyzer;

import static java.util.Objects.isNull;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lemakhno.threatanalyzer.config.Constants;
import com.lemakhno.threatanalyzer.config.Threats;
import com.lemakhno.threatanalyzer.entity.ThreatEntity;
import com.lemakhno.threatanalyzer.model.RequestDetails;
import com.lemakhno.threatanalyzer.repository.ThreatRepository;

@Component
public class BruteForceDetector {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private ThreatRepository threatRepository;
    
    private Map<String, LinkedList<LocalDateTime>> map;

    public BruteForceDetector() {
        this.map = new ConcurrentHashMap<>();
    }

    public void check(RequestDetails requestDetails) {
        logger.info("Checking brute force attempt for host: {}", requestDetails.getSourceHost());
        LocalDateTime dateTimeNow = LocalDateTime.now();

        LinkedList<LocalDateTime> hostRequestHistory = map.get(requestDetails.getSourceHost());

        if (isNull(hostRequestHistory)) {
            LinkedList<LocalDateTime> newHostRequestHistory = new LinkedList<>();
            newHostRequestHistory.add(dateTimeNow);
            map.put(requestDetails.getSourceHost(), newHostRequestHistory);
            logger.info("First request from host, created entry: {}", newHostRequestHistory);
            return;
        }

        hostRequestHistory.add(dateTimeNow);
        logger.info("Request history for host {}: {}", requestDetails.getSourceHost(), hostRequestHistory);
        if (hostRequestHistory.size() == 1)
            return;
        
        int requestsOverLastSecond = 1;

        int idx = hostRequestHistory.size() - 2;

        while (idx >= 0) {
            if (getSecondsBetween(hostRequestHistory.get(idx), dateTimeNow) > 1)
                break;
            requestsOverLastSecond++;
            idx--;
        }

        if (requestsOverLastSecond > Constants.ALLOWED_REQUESTS_PER_SECOND) {
            ThreatEntity threatEntity = new ThreatEntity()
                .setDateTime(dateTimeNow)
                .setType(Threats.BRUTE_FORCE.getTypeDescription())
                .setSourceHost(requestDetails.getSourceHost())
                .setDetails("Endpoint: " + requestDetails.getEndpoint() + ", Method: " + requestDetails.getMethod() + ", RPS: " + requestsOverLastSecond);
            ThreatEntity savedThreatEntity = threatRepository.save(threatEntity);
            logger.info("New brute force threat record: {}", savedThreatEntity.getId());
            hostRequestHistory.clear();
        }

        if (hostRequestHistory.size() > 100)
            hostRequestHistory.clear();
    }

    private long getSecondsBetween(LocalDateTime dateTimeA, LocalDateTime dateTimeB) {
        return ChronoUnit.SECONDS.between(dateTimeA, dateTimeB);
    }
}
