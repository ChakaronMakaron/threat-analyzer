package com.lemakhno.threatanalyzer.utils;

import static java.util.Objects.nonNull;

import java.io.BufferedReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class AppUtils {
    
    public static Map<String, String> formDataToMap(BufferedReader reader) {
        Map<String, String> resultMap = new HashMap<>();
        try {
            String data = "";
            String line;
            while (nonNull(line = reader.readLine())) {
                data += line;
            }
            Arrays.asList(data.split("&")).forEach(item -> {
                String[] keyValue = item.split("=");
                resultMap.put(keyValue[0], keyValue[1]);
            });
        } catch (Exception exception) {}
        finally {
            try {
                reader.close();
            } catch (Exception e) {}
        }
        return resultMap;
    }
}
