package com.lemakhno.threatanalyzer.security.servlet.wrapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;

public class CachedBodyServletInputStream extends ServletInputStream {

    private InputStream cachedBodyInputStream;

    public CachedBodyServletInputStream(byte[] cachedBody) {
        this.cachedBodyInputStream = new ByteArrayInputStream(cachedBody);
    }

    @Override
    public boolean isFinished() {
        int available = 0;
        try {
            available = cachedBodyInputStream.available();
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }
        return available == 0;
    }

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public void setReadListener(ReadListener listener) {}

    @Override
    public int read() throws IOException {
        return cachedBodyInputStream.read();
    }
}
