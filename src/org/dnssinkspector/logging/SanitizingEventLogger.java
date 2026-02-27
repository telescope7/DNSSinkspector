package org.dnssinkspector.logging;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class SanitizingEventLogger implements EventLogger {
    private final EventLogger delegate;
    private final Set<String> excludedFields;

    public SanitizingEventLogger(EventLogger delegate, Set<String> excludedFields) {
        this.delegate = delegate;
        this.excludedFields = Set.copyOf(excludedFields);
    }

    @Override
    public void logEvent(Map<String, Object> event) {
        Map<String, Object> sanitized = new LinkedHashMap<>(event);
        for (String field : excludedFields) {
            sanitized.remove(field);
        }
        delegate.logEvent(sanitized);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
