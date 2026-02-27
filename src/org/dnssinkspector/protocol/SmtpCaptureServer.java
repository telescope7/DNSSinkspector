package org.dnssinkspector.protocol;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;

public final class SmtpCaptureServer extends AbstractTcpCaptureServer {
    public SmtpCaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        super("SMTP", config, eventLogger);
    }

    @Override
    protected TcpSessionCapture captureSession(Socket socket) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

        writeLine(writer, "220 DNSSinkspector SMTP Service Ready");

        String username = null;
        String password = null;
        StringBuilder captured = new StringBuilder();
        int[] capturedBytes = new int[] { 0 };
        boolean[] truncated = new boolean[] { false };

        while (true) {
            String line;
            try {
                line = readLineAndCapture(reader, captured, capturedBytes, truncated, getConfig().getCaptureMaxBytes());
            } catch (SocketTimeoutException e) {
                break;
            }
            if (line == null) {
                break;
            }

            String upper = line.toUpperCase(Locale.ROOT);

            if (upper.startsWith("AUTH LOGIN")) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 3) {
                    String decoded = TcpCaptureUtil.decodeBase64Loose(parts[2].trim());
                    if (decoded != null) {
                        username = decoded.trim();
                    }
                } else {
                    writeLine(writer, "334 VXNlcm5hbWU6");
                    String userLine;
                    try {
                        userLine = readLineAndCapture(
                                reader,
                                captured,
                                capturedBytes,
                                truncated,
                                getConfig().getCaptureMaxBytes());
                    } catch (SocketTimeoutException e) {
                        break;
                    }
                    if (userLine == null) {
                        break;
                    }
                    String decoded = TcpCaptureUtil.decodeBase64Loose(userLine.trim());
                    if (decoded != null) {
                        username = decoded.trim();
                    }
                }

                writeLine(writer, "334 UGFzc3dvcmQ6");
                String passLine;
                try {
                    passLine = readLineAndCapture(reader, captured, capturedBytes, truncated, getConfig().getCaptureMaxBytes());
                } catch (SocketTimeoutException e) {
                    break;
                }
                if (passLine == null) {
                    break;
                }
                String decodedPassword = TcpCaptureUtil.decodeBase64Loose(passLine.trim());
                if (decodedPassword != null) {
                    password = decodedPassword.trim();
                }

                writeLine(writer, "235 Authentication successful");
                continue;
            }

            if (upper.startsWith("AUTH PLAIN")) {
                String token = null;
                String[] parts = line.split("\\s+");
                if (parts.length >= 3) {
                    token = parts[2].trim();
                } else {
                    writeLine(writer, "334");
                    String authLine;
                    try {
                        authLine = readLineAndCapture(
                                reader,
                                captured,
                                capturedBytes,
                                truncated,
                                getConfig().getCaptureMaxBytes());
                    } catch (SocketTimeoutException e) {
                        break;
                    }
                    if (authLine == null) {
                        break;
                    }
                    token = authLine.trim();
                }

                String decoded = TcpCaptureUtil.decodeBase64Loose(token);
                if (decoded != null) {
                    String[] segments = TcpCaptureUtil.stripControlPrefix(decoded).split("\u0000");
                    if (segments.length >= 2) {
                        username = segments[0];
                        password = segments[1];
                    }
                }
                writeLine(writer, "235 Authentication successful");
                continue;
            }

            if (upper.startsWith("DATA")) {
                writeLine(writer, "354 End data with <CR><LF>.<CR><LF>");
                while (true) {
                    String dataLine;
                    try {
                        dataLine = readLineAndCapture(
                                reader,
                                captured,
                                capturedBytes,
                                truncated,
                                getConfig().getCaptureMaxBytes());
                    } catch (SocketTimeoutException e) {
                        dataLine = null;
                    }
                    if (dataLine == null || ".".equals(dataLine) || truncated[0]) {
                        break;
                    }
                }
                writeLine(writer, "250 Message accepted");
                if (truncated[0]) {
                    break;
                }
                continue;
            }

            if (upper.startsWith("QUIT")) {
                writeLine(writer, "221 Bye");
                break;
            }

            writeLine(writer, "250 OK");
        }

        byte[] payload = captured.toString().getBytes(StandardCharsets.UTF_8);
        return new TcpSessionCapture(
                username,
                password,
                captured.toString(),
                TcpCaptureUtil.toBase64(payload),
                payload.length,
                truncated[0],
                "captured_and_closed",
                null);
    }

    private static String readLineAndCapture(
            BufferedReader reader,
            StringBuilder captured,
            int[] capturedBytes,
            boolean[] truncated,
            int maxCaptureBytes) throws IOException {
        String line = reader.readLine();
        if (line == null) {
            return null;
        }
        int lineBytes = line.getBytes(StandardCharsets.UTF_8).length + 1;
        if (capturedBytes[0] + lineBytes > maxCaptureBytes) {
            truncated[0] = true;
            return null;
        }
        captured.append(line).append('\n');
        capturedBytes[0] += lineBytes;
        return line;
    }

    private static void writeLine(BufferedWriter writer, String line) throws IOException {
        writer.write(line);
        writer.write("\r\n");
        writer.flush();
    }
}
