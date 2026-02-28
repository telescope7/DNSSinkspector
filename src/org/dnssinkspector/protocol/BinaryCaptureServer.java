package org.dnssinkspector.protocol;

import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;

public final class BinaryCaptureServer extends AbstractTcpCaptureServer {
    private final byte[] greetingBytes;

    public BinaryCaptureServer(
            String protocolName,
            TcpServiceConfig config,
            EventLogger eventLogger,
            String greeting) {
        super(protocolName, config, eventLogger);
        this.greetingBytes = greeting == null
                ? new byte[0]
                : greeting.getBytes(StandardCharsets.US_ASCII);
    }

    @Override
    protected TcpSessionCapture captureSession(Socket socket) throws IOException {
        if (greetingBytes.length > 0) {
            try {
                socket.getOutputStream().write(greetingBytes);
                socket.getOutputStream().flush();
            } catch (IOException e) {
                // Continue and log inbound payload even if greeting cannot be delivered.
            }
        }

        TcpCaptureUtil.ReadResult readResult = TcpCaptureUtil.readUpTo(
                socket.getInputStream(),
                getConfig().getCaptureMaxBytes());
        byte[] payload = readResult.payload();
        String decision = payload.length == 0
                ? "captured_no_data_and_closed"
                : readResult.truncated() ? "captured_truncated_and_closed" : "captured_and_closed";

        return new TcpSessionCapture(
                null,
                null,
                TcpCaptureUtil.toUtf8(payload),
                TcpCaptureUtil.toBase64(payload),
                payload.length,
                readResult.truncated(),
                decision,
                null);
    }
}
