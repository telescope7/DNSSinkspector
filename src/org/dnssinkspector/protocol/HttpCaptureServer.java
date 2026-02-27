package org.dnssinkspector.protocol;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;
import org.dnssinkspector.protocol.TcpCaptureUtil.ReadResult;

public final class HttpCaptureServer extends AbstractTcpCaptureServer {
    private static final Pattern BASIC_AUTH_PATTERN = Pattern.compile(
            "(?im)^Authorization\\s*:\\s*Basic\\s+([A-Za-z0-9+/=]+)\\s*$");

    public HttpCaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        super("HTTP", config, eventLogger);
    }

    @Override
    protected TcpSessionCapture captureSession(Socket socket) throws IOException {
        ReadResult readResult = TcpCaptureUtil.readBurst(socket.getInputStream(), getConfig().getCaptureMaxBytes());
        byte[] payload = readResult.payload();
        String dataText = TcpCaptureUtil.toUtf8(payload);

        String username = null;
        String password = null;
        Matcher authMatcher = BASIC_AUTH_PATTERN.matcher(dataText);
        if (authMatcher.find()) {
            String decoded = TcpCaptureUtil.decodeBase64Loose(authMatcher.group(1));
            if (decoded != null) {
                int separator = decoded.indexOf(':');
                if (separator >= 0) {
                    username = decoded.substring(0, separator);
                    password = decoded.substring(separator + 1);
                } else {
                    username = decoded;
                }
            }
        }

        String body = "OK\n";
        String response = "HTTP/1.1 200 OK\r\n"
                + "Server: DNSSinkspector\r\n"
                + "Connection: close\r\n"
                + "Content-Type: text/plain\r\n"
                + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                + "\r\n"
                + body;
        OutputStream out = socket.getOutputStream();
        out.write(response.getBytes(StandardCharsets.UTF_8));
        out.flush();

        return new TcpSessionCapture(
                username,
                password,
                dataText,
                TcpCaptureUtil.toBase64(payload),
                payload.length,
                readResult.truncated(),
                "captured_and_closed",
                null);
    }
}
