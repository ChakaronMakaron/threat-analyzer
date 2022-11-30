package com.lemakhno.threatanalyzer.utils;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import java.io.BufferedReader;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lemakhno.threatanalyzer.model.RequestDetails;

public class AppUtils {

    private static Logger logger = LoggerFactory.getLogger(AppUtils.class);
    
    public static Map<String, String> formDataToMap(BufferedReader reader) {
        Map<String, String> resultMap = new HashMap<>();
        try {
            String data = "";
            String line;
            while (nonNull(line = reader.readLine())) {
                data += line;
            }
            if (!data.isEmpty()) {
                Arrays.asList(data.split("&")).forEach(item -> {
                    String[] keyValue = item.split("=");
                    resultMap.put(keyValue[0], keyValue[1]);
                });
            }
        } catch (Exception exception) {
            logger.info("EXCEPTION >>> {}", exception.getMessage());
        }
        return resultMap;
    }

    public static Map<String, String> objectToMap(Object object) {
        Map<String, String> resultMap = new HashMap<>();
        try {
            for (Field field : object.getClass().getDeclaredFields()) {
                field.setAccessible(true);
                Object fieldValue = field.get(object);
                resultMap.put(field.getName(), isNull(fieldValue) ? null : fieldValue.toString());
            }
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
        return resultMap;
    }

    public static RequestDetails getRequestDetails(HttpServletRequest request) {
        return new RequestDetails()
            .setEndpoint(request.getRequestURI())
            .setSourceHost(isNullOrBlank(request.getHeader("Host")) ? "Caller address unavailable" : request.getHeader("Host"))
            .setMethod(request.getMethod());
    }

    public static boolean isNullOrBlank(String string) {
        if (string == null) return true;
        if (string.isEmpty()) return true;
        return false;
    }

    public static String cookiesToString(Cookie[] cookies) {
        String result = "";
        for (Cookie cookie : cookies) {
            result += String.format("{%s=%s}", cookie.getName(), cookie.getValue());
        }
        return result.isBlank() ? "No cookies" : result;
    }
}
