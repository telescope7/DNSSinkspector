package org.dnssinkspector.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;

public final class ImapCaptureServer extends AbstractTcpCaptureServer {
    public ImapCaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        super("IMAP", config, eventLogger);
    }

    @Override
    protected TcpSessionCapture captureSession(Socket socket) throws IOException {
        CaptureBuffer captureBuffer = new CaptureBuffer(getConfig().getCaptureMaxBytes());
        String username = null;
        String password = null;
        String decision = "captured_and_closed";
        String error = null;
        String authTag = null;
        boolean expectAuthLoginUser = false;
        boolean expectAuthLoginPassword = false;

        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        sendLine(out, "* OK DNSSinkspector IMAP service ready");

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
                sendTaggedOk(out, authTag, "AUTHENTICATE completed");
                break;
            }

            ImapCommand command = ImapCommand.parse(trimmed);
            if (command == null) {
                continue;
            }

            if ("LOGIN".equals(command.command())) {
                username = command.argument(0);
                password = command.argument(1);
                decision = "captured_credentials_and_closed";
                sendTaggedOk(out, command.tag(), "LOGIN completed");
                break;
            }

            if ("AUTHENTICATE".equals(command.command())) {
                String mechanism = command.argumentUpper(0);
                if ("PLAIN".equals(mechanism)) {
                    String initialResponse = command.argument(1);
                    if (initialResponse == null || initialResponse.isBlank() || "=".equals(initialResponse)) {
                        sendLine(out, "+");
                        String continuation = readLine(in);
                        if (continuation != null) {
                            captureBuffer.appendLine(continuation);
                            initialResponse = continuation.trim();
                        }
                    }
                    Credentials credentials = decodeSaslPlain(initialResponse);
                    if (credentials != null) {
                        username = credentials.username();
                        password = credentials.password();
                        decision = "captured_credentials_and_closed";
                    }
                    sendTaggedOk(out, command.tag(), "AUTHENTICATE completed");
                    break;
                }
                if ("LOGIN".equals(mechanism)) {
                    authTag = command.tag();
                    String initialResponse = command.argument(1);
                    if (initialResponse == null || initialResponse.isBlank() || "=".equals(initialResponse)) {
                        expectAuthLoginUser = true;
                        sendLine(out, "+ VXNlcm5hbWU6");
                    } else {
                        username = decodeBase64Value(initialResponse);
                        expectAuthLoginPassword = true;
                        sendLine(out, "+ UGFzc3dvcmQ6");
                    }
                    continue;
                }

                sendTaggedNo(out, command.tag(), "Unsupported AUTH mechanism");
                continue;
            }

            if ("LOGOUT".equals(command.command())) {
                sendLine(out, "* BYE Logging session");
                sendTaggedOk(out, command.tag(), "LOGOUT completed");
                decision = "captured_and_closed";
                break;
            }

            sendTaggedOk(out, command.tag(), "Command noted");
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
                error);
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

    private static void sendTaggedOk(OutputStream out, String tag, String message) throws IOException {
        sendLine(out, safeTag(tag) + " OK " + message);
    }

    private static void sendTaggedNo(OutputStream out, String tag, String message) throws IOException {
        sendLine(out, safeTag(tag) + " NO " + message);
    }

    private static String safeTag(String tag) {
        if (tag == null || tag.isBlank()) {
            return "*";
        }
        return tag;
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

    private record ImapCommand(String tag, String command, List<String> arguments) {
        private static ImapCommand parse(String line) {
            List<String> tokens = splitTokens(line);
            if (tokens.size() < 2) {
                return null;
            }
            String tag = tokens.get(0);
            String command = tokens.get(1).toUpperCase(Locale.ROOT);
            List<String> arguments = tokens.size() > 2
                    ? List.copyOf(tokens.subList(2, tokens.size()))
                    : List.of();
            return new ImapCommand(tag, command, arguments);
        }

        private String argument(int index) {
            if (index < 0 || index >= arguments.size()) {
                return null;
            }
            return arguments.get(index);
        }

        private String argumentUpper(int index) {
            String value = argument(index);
            return value == null ? null : value.toUpperCase(Locale.ROOT);
        }

        private static List<String> splitTokens(String value) {
            List<String> tokens = new ArrayList<>();
            StringBuilder current = new StringBuilder();
            boolean inQuotes = false;
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c == '"') {
                    inQuotes = !inQuotes;
                    continue;
                }
                if (Character.isWhitespace(c) && !inQuotes) {
                    if (current.length() > 0) {
                        tokens.add(current.toString());
                        current.setLength(0);
                    }
                    continue;
                }
                current.append(c);
            }
            if (current.length() > 0) {
                tokens.add(current.toString());
            }
            return tokens;
        }
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
