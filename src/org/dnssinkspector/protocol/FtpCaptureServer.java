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

public final class FtpCaptureServer extends AbstractTcpCaptureServer {
    public FtpCaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        super("FTP", config, eventLogger);
    }

    @Override
    protected TcpSessionCapture captureSession(Socket socket) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

        writeLine(writer, "220 DNSSinkspector FTP Service Ready");

        String username = null;
        String password = null;
        StringBuilder captured = new StringBuilder();
        int capturedBytes = 0;
        boolean truncated = false;

        while (true) {
            String line;
            try {
                line = reader.readLine();
            } catch (SocketTimeoutException e) {
                break;
            }
            if (line == null) {
                break;
            }

            int lineBytes = line.getBytes(StandardCharsets.UTF_8).length + 1;
            if (capturedBytes + lineBytes > getConfig().getCaptureMaxBytes()) {
                truncated = true;
                break;
            }
            captured.append(line).append('\n');
            capturedBytes += lineBytes;

            String upper = line.toUpperCase(Locale.ROOT);
            if (upper.startsWith("USER ")) {
                username = line.substring(5).trim();
                writeLine(writer, "331 Username OK, need password");
                continue;
            }
            if (upper.startsWith("PASS ")) {
                password = line.substring(5).trim();
                writeLine(writer, "230 User logged in");
                break;
            }
            if (upper.startsWith("QUIT")) {
                writeLine(writer, "221 Goodbye");
                break;
            }

            writeLine(writer, "200 OK");
        }

        byte[] payload = captured.toString().getBytes(StandardCharsets.UTF_8);
        return new TcpSessionCapture(
                username,
                password,
                captured.toString(),
                TcpCaptureUtil.toBase64(payload),
                payload.length,
                truncated,
                "captured_and_closed",
                null);
    }

    private static void writeLine(BufferedWriter writer, String line) throws IOException {
        writer.write(line);
        writer.write("\r\n");
        writer.flush();
    }
}
