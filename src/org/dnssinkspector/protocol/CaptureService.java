package org.dnssinkspector.protocol;

import java.io.IOException;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;

public interface CaptureService {
    void start() throws IOException;

    void stop();

    String getProtocolName();

    TcpServiceConfig getConfig();
}
