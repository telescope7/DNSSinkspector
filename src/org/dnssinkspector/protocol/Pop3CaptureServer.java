package org.dnssinkspector.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;

public final class Pop3CaptureServer extends AbstractTcpCaptureServer {
    public Pop3CaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        super("POP3", config, eventLogger);
    }

    @Override
    protected TcpSessionCapture captureSession(Socket socket) throws IOException {
        CaptureBuffer captureBuffer = new CaptureBuffer(getConfig().getCaptureMaxBytes());
        String username = null;
        String password = null;
        String decision = "captured_and_closed";
        boolean expectAuthPlain = false;
        boolean expectAuthLoginUser = false;
        boolean expectAuthLoginPassword = false;

        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        sendLine(out, "+OK DNSSinkspector POP3 service ready");

        while (!captureBuffer.isTruncated()) {
            String line = readLine(in);
            if (line == null) {
                break;
            }
            captureBuffer.appendLine(line);
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }

            if (expectAuthPlain) {
                Credentials credentials = decodeSaslPlain(trimmed);
                if (credentials != null) {
                    username = credentials.username();
                    password = credentials.password();
                    decision = "captured_credentials_and_closed";
                }
                sendLine(out, "+OK AUTH complete");
                break;
            }

            if (expectAuthLoginUser) {
                username = decodeBase64Value(trimmed);
                expectAuthLoginUser = false;
                expectAuthLoginPassword = true;
                sendLine(out, "+ UGFzc3dvcmQ6");
                continue;
            }

            if (expectAuthLoginPassword) {
                password = decodeBase64Value(trimmed);
                decision = "captured_credentials_and_closed";
                sendLine(out, "+OK AUTH complete");
                break;
            }

            String[] parts = splitCommand(trimmed);
            String command = parts[0].toUpperCase(Locale.ROOT);
            String argument = parts[1];

            if ("USER".equals(command)) {
                username = argument;
                sendLine(out, "+OK user noted");
                continue;
            }

            if ("PASS".equals(command)) {
                password = argument;
                decision = "captured_credentials_and_closed";
                sendLine(out, "+OK mailbox locked and ready");
                break;
            }

            if ("APOP".equals(command)) {
                String[] apopArgs = argument == null ? new String[0] : argument.split("\\s+", 2);
                if (apopArgs.length > 0) {
                    username = apopArgs[0];
                }
                if (apopArgs.length > 1) {
                    password = apopArgs[1];
                }
                decision = "captured_credentials_and_closed";
                sendLine(out, "+OK mailbox locked and ready");
                break;
            }

            if ("AUTH".equals(command)) {
                String mechanism = argument == null ? "" : argument.toUpperCase(Locale.ROOT);
                if (mechanism.startsWith("PLAIN")) {
                    String[] authParts = argument.split("\\s+", 2);
                    if (authParts.length > 1) {
                        Credentials credentials = decodeSaslPlain(authParts[1]);
                        if (credentials != null) {
                            username = credentials.username();
                            password = credentials.password();
                            decision = "captured_credentials_and_closed";
                        }
                        sendLine(out, "+OK AUTH complete");
                        break;
                    }
                    expectAuthPlain = true;
                    sendLine(out, "+");
                    continue;
                }
                if (mechanism.startsWith("LOGIN")) {
                    String[] authParts = argument.split("\\s+", 2);
                    if (authParts.length > 1) {
                        username = decodeBase64Value(authParts[1]);
                        expectAuthLoginPassword = true;
                        sendLine(out, "+ UGFzc3dvcmQ6");
                    } else {
                        expectAuthLoginUser = true;
                        sendLine(out, "+ VXNlcm5hbWU6");
                    }
                    continue;
                }
                sendLine(out, "-ERR unsupported AUTH mechanism");
                continue;
            }

            if ("QUIT".equals(command)) {
                decision = "captured_and_closed";
                sendLine(out, "+OK bye");
                break;
            }

            sendLine(out, "+OK");
        }

        if (captureBuffer.isTruncated() && "captured_and_closed".equals(decision)) {
            decision = "captured_truncated_and_closed";
        } else if (captureBuffer.size() == 0 && "captured_and_closed".equals(decision)) {
            decision = "captured_no_data_and_closed";
        }

        byte[] payload = captureBuffer.snapshot();
        return new TcpSessionCapture(
                username,
                password,
                new String(payload, StandardCharsets.UTF_8),
                Base64.getEncoder().encodeToString(payload),
                payload.length,
                captureBuffer.isTruncated(),
                decision,
                null);
    }

    private static Credentials decodeSaslPlain(String value) {
        String decoded = decodeBase64Value(value);
        if (decoded == null) {
            return null;
        }
        String[] chunks = decoded.split("\u0000", -1);
        if (chunks.length < 3) {
            return null;
        }
        String username = chunks[chunks.length - 2];
        String password = chunks[chunks.length - 1];
        return new Credentials(username, password);
    }

    private static String decodeBase64Value(String raw) {
        if (raw == null) {
            return null;
        }
        String decoded = TcpCaptureUtil.decodeBase64Loose(raw.trim());
        if (decoded == null) {
            return null;
        }
        return TcpCaptureUtil.stripControlPrefix(decoded);
    }

    private static String[] splitCommand(String line) {
        int separator = line.indexOf(' ');
        if (separator < 0) {
            return new String[] { line, null };
        }
        String command = line.substring(0, separator);
        String argument = line.substring(separator + 1).trim();
        return new String[] { command, argument.isEmpty() ? null : argument };
    }

    private static void sendLine(OutputStream out, String line) throws IOException {
        out.write((line + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        while (line.size() < 8192) {
            int b;
            try {
                b = in.read();
            } catch (SocketTimeoutException e) {
                return line.size() == 0 ? null : line.toString(StandardCharsets.UTF_8);
            }
            if (b == -1) {
                return line.size() == 0 ? null : line.toString(StandardCharsets.UTF_8);
            }
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                line.write(b);
            }
        }
        return line.toString(StandardCharsets.UTF_8);
    }

    private record Credentials(String username, String password) {
    }

    private static final class CaptureBuffer {
        private final int maxBytes;
        private final ByteArrayOutputStream payload = new ByteArrayOutputStream();
        private boolean truncated;

        private CaptureBuffer(int maxBytes) {
            this.maxBytes = maxBytes;
        }

        private void appendLine(String line) {
            append((line + "\n").getBytes(StandardCharsets.UTF_8));
        }

        private void append(byte[] bytes) {
            if (truncated || bytes.length == 0) {
                return;
            }
            int remaining = maxBytes - payload.size();
            if (remaining <= 0) {
                truncated = true;
                return;
            }
            int toWrite = Math.min(remaining, bytes.length);
            payload.write(bytes, 0, toWrite);
            if (toWrite < bytes.length) {
                truncated = true;
            }
        }

        private boolean isTruncated() {
            return truncated;
        }

        private int size() {
            return payload.size();
        }

        private byte[] snapshot() {
            return payload.toByteArray();
        }
    }
}
