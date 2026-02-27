package org.dnssinkspector.logging;

import java.io.Closeable;
import java.util.Map;

public interface EventLogger extends Closeable {
    void logEvent(Map<String, Object> event);
}
