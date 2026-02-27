package org.dnssinkspector.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

final class TcpCaptureUtil {
    private TcpCaptureUtil() {
    }

    static ReadResult readUpTo(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxBytes, 4096));
        byte[] buffer = new byte[1024];
        boolean truncated = false;

        while (true) {
            int remaining = maxBytes - out.size();
            if (remaining <= 0) {
                try {
                    int extra = in.read();
                    if (extra != -1) {
                        truncated = true;
                    }
                } catch (SocketTimeoutException e) {
                    // Connection became idle right at capture limit.
                }
                break;
            }

            int read;
            try {
                read = in.read(buffer, 0, Math.min(buffer.length, remaining));
            } catch (SocketTimeoutException e) {
                break;
            }
            if (read == -1) {
                break;
            }
            if (read == 0) {
                continue;
            }
            out.write(buffer, 0, read);
        }

        return new ReadResult(out.toByteArray(), truncated);
    }

    static ReadResult readBurst(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxBytes, 4096));
        byte[] buffer = new byte[1024];
        boolean truncated = false;

        int firstRead = in.read(buffer, 0, Math.min(buffer.length, maxBytes));
        if (firstRead == -1) {
            return new ReadResult(new byte[0], false);
        }
        out.write(buffer, 0, firstRead);

        while (out.size() < maxBytes && in.available() > 0) {
            int remaining = maxBytes - out.size();
            int read = in.read(buffer, 0, Math.min(buffer.length, remaining));
            if (read == -1) {
                break;
            }
            out.write(buffer, 0, read);
        }

        if (out.size() >= maxBytes && in.available() > 0) {
            truncated = true;
        }

        return new ReadResult(out.toByteArray(), truncated);
    }

    static String toUtf8(byte[] payload) {
        return new String(payload, StandardCharsets.UTF_8);
    }

    static String toBase64(byte[] payload) {
        return Base64.getEncoder().encodeToString(payload);
    }

    static String decodeBase64Loose(String value) {
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    static String stripControlPrefix(String raw) {
        if (raw == null) {
            return null;
        }
        int i = 0;
        while (i < raw.length() && raw.charAt(i) == '\0') {
            i++;
        }
        return raw.substring(i);
    }

    static final class ReadResult {
        private final byte[] payload;
        private final boolean truncated;

        ReadResult(byte[] payload, boolean truncated) {
            this.payload = payload;
            this.truncated = truncated;
        }

        byte[] payload() {
            return payload;
        }

        boolean truncated() {
            return truncated;
        }
    }
}
