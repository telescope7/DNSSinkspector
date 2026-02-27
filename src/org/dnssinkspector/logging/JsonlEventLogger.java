package org.dnssinkspector.logging;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public final class JsonlEventLogger implements EventLogger {
    private final BufferedWriter writer;

    public JsonlEventLogger(Path logPath) throws IOException {
        Path parent = logPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        this.writer = Files.newBufferedWriter(
                logPath,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
    }

    public synchronized void logEvent(Map<String, Object> event) {
        try {
            writer.write(toJson(event));
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            System.err.println("Failed to write log event: " + e.getMessage());
        }
    }

    @Override
    public synchronized void close() {
        try {
            writer.close();
        } catch (IOException e) {
            System.err.println("Failed to close log writer: " + e.getMessage());
        }
    }

    private static String toJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String) {
            return "\"" + escape((String) value) + "\"";
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        }
        if (value instanceof List<?>) {
            StringBuilder out = new StringBuilder();
            out.append('[');
            Iterator<?> it = ((List<?>) value).iterator();
            while (it.hasNext()) {
                out.append(toJson(it.next()));
                if (it.hasNext()) {
                    out.append(',');
                }
            }
            out.append(']');
            return out.toString();
        }
        if (value instanceof Map<?, ?>) {
            StringBuilder out = new StringBuilder();
            out.append('{');
            Iterator<? extends Map.Entry<?, ?>> it = ((Map<?, ?>) value).entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<?, ?> entry = it.next();
                out.append(toJson(String.valueOf(entry.getKey())));
                out.append(':');
                out.append(toJson(entry.getValue()));
                if (it.hasNext()) {
                    out.append(',');
                }
            }
            out.append('}');
            return out.toString();
        }
        return toJson(value.toString());
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
            case '"':
                out.append("\\\"");
                break;
            case '\\':
                out.append("\\\\");
                break;
            case '\b':
                out.append("\\b");
                break;
            case '\f':
                out.append("\\f");
                break;
            case '\n':
                out.append("\\n");
                break;
            case '\r':
                out.append("\\r");
                break;
            case '\t':
                out.append("\\t");
                break;
            default:
                if (c < 0x20) {
                    out.append(String.format("\\u%04x", (int) c));
                } else {
                    out.append(c);
                }
                break;
            }
        }
        return out.toString();
    }
}
