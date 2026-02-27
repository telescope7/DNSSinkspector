package org.dnssinkspector.logging;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public final class CompositeEventLogger implements EventLogger {
    private final List<EventLogger> delegates;

    public CompositeEventLogger(List<EventLogger> delegates) {
        this.delegates = List.copyOf(delegates);
    }

    @Override
    public void logEvent(Map<String, Object> event) {
        for (EventLogger logger : delegates) {
            logger.logEvent(event);
        }
    }

    @Override
    public void close() {
        IOException first = null;
        for (EventLogger logger : delegates) {
            try {
                logger.close();
            } catch (IOException e) {
                if (first == null) {
                    first = e;
                }
            }
        }
        if (first != null) {
            System.err.println("Failed to close one or more loggers: " + first.getMessage());
        }
    }
}
