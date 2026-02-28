package org.dnssinkspector.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;

public final class HttpCaptureServer implements CaptureService {
    private static final byte[] OK_BODY = "OK\n".getBytes(StandardCharsets.UTF_8);
    private static final byte[] ERROR_BODY = "ERROR\n".getBytes(StandardCharsets.UTF_8);

    private final TcpServiceConfig config;
    private final EventLogger eventLogger;
    private final String protocolName;
    private final AtomicLong sessionCounter = new AtomicLong(0);

    private HttpServer httpServer;
    private ExecutorService executor;

    public HttpCaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        this(config, eventLogger, null);
    }

    public HttpCaptureServer(TcpServiceConfig config, EventLogger eventLogger, String protocolNameOverride) {
        this.config = config;
        this.eventLogger = eventLogger;
        String fallbackName = config.isTlsEnabled() ? "HTTPS" : "HTTP";
        this.protocolName = protocolNameOverride == null || protocolNameOverride.isBlank()
                ? fallbackName
                : protocolNameOverride;
    }

    @Override
    public synchronized void start() throws IOException {
        if (httpServer != null) {
            return;
        }

        InetSocketAddress bindAddress = new InetSocketAddress(config.getListenAddress(), config.getListenPort());
        HttpServer server = createServer(bindAddress);
        ExecutorService serverExecutor = Executors.newCachedThreadPool();
        server.setExecutor(serverExecutor);
        server.createContext("/", new CaptureHandler());
        server.start();
        httpServer = server;
        executor = serverExecutor;
    }

    @Override
    public synchronized void stop() {
        if (httpServer != null) {
            httpServer.stop(0);
            httpServer = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            try {
                executor.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            executor = null;
        }
    }

    @Override
    public String getProtocolName() {
        return protocolName;
    }

    @Override
    public TcpServiceConfig getConfig() {
        return config;
    }

    private HttpServer createServer(InetSocketAddress bindAddress) throws IOException {
        if (!config.isTlsEnabled()) {
            return HttpServer.create(bindAddress, 0);
        }

        SSLContext sslContext = buildSslContext();
        HttpsServer httpsServer = HttpsServer.create(bindAddress, 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                params.setSSLParameters(sslContext.getDefaultSSLParameters());
            }
        });
        return httpsServer;
    }

    private SSLContext buildSslContext() throws IOException {
        char[] storePassword = config.getTlsKeystorePassword().toCharArray();
        char[] keyPassword = config.getTlsKeyPassword().isEmpty()
                ? storePassword
                : config.getTlsKeyPassword().toCharArray();

        try (InputStream keystoreStream = Files.newInputStream(Path.of(config.getTlsKeystorePath()))) {
            KeyStore keyStore = KeyStore.getInstance(config.getTlsKeystoreType());
            keyStore.load(keystoreStream, storePassword);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keyPassword);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);
            return sslContext;
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to initialize HTTPS context: " + e.getMessage(), e);
        }
    }

    private final class CaptureHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) {
            long startedAtNanos = System.nanoTime();
            String protocolName = getProtocolName();
            String sessionId = protocolName + "-" + sessionCounter.incrementAndGet();
            InetSocketAddress remote = exchange.getRemoteAddress();
            InetSocketAddress local = exchange.getLocalAddress();

            CaptureBuffer captureBuffer = new CaptureBuffer(config.getCaptureMaxBytes());
            String username = null;
            String password = null;
            String decision = "captured_and_closed";
            String error = null;

            try {
                appendRequestLine(exchange, captureBuffer);
                appendHeaders(exchange.getRequestHeaders(), captureBuffer);

                Credentials credentials = extractBasicCredentials(exchange.getRequestHeaders());
                if (credentials != null) {
                    username = credentials.username();
                    password = credentials.password();
                    decision = "captured_credentials_and_closed";
                }

                try (InputStream body = exchange.getRequestBody()) {
                    byte[] chunk = new byte[1024];
                    while (!captureBuffer.isTruncated()) {
                        int read = body.read(chunk);
                        if (read == -1) {
                            break;
                        }
                        if (read > 0) {
                            captureBuffer.append(chunk, 0, read);
                        }
                    }
                }

                if (captureBuffer.isTruncated() && "captured_and_closed".equals(decision)) {
                    decision = "captured_truncated_and_closed";
                }
                sendResponse(exchange, 200, OK_BODY);
            } catch (Exception e) {
                error = e.getMessage();
                decision = "capture_error";
                sendResponse(exchange, 500, ERROR_BODY);
            } finally {
                exchange.close();
                long latencyMs = (System.nanoTime() - startedAtNanos) / 1_000_000L;
                Map<String, Object> event = new LinkedHashMap<>();
                event.put("timestamp_utc", Instant.now().toString());
                event.put("event_type", "tcp_session");
                event.put("protocol", protocolName);
                event.put("transport", "tcp");
                event.put("client_ip", host(remote));
                event.put("client_port", port(remote));
                event.put("server_ip", host(local));
                event.put("server_port", port(local));
                event.put("session_id", sessionId);
                event.put("decision", decision);
                event.put("username", username);
                event.put("password", password);
                byte[] payload = captureBuffer.snapshot();
                event.put("data_text", new String(payload, StandardCharsets.UTF_8));
                event.put("data_base64", Base64.getEncoder().encodeToString(payload));
                event.put("request_size_bytes", payload.length);
                event.put("truncated", captureBuffer.isTruncated());
                event.put("error", error);
                event.put("latency_ms", latencyMs);
                eventLogger.logEvent(event);
            }
        }
    }

    private static void appendRequestLine(HttpExchange exchange, CaptureBuffer captureBuffer) {
        URI uri = exchange.getRequestURI();
        String path = uri == null ? "/" : uri.getRawPath();
        if (path == null || path.isBlank()) {
            path = "/";
        }
        String query = (uri == null) ? null : uri.getRawQuery();
        if (query != null && !query.isBlank()) {
            path = path + "?" + query;
        }
        captureBuffer.appendLine(exchange.getRequestMethod() + " " + path + " " + exchange.getProtocol());
    }

    private static void appendHeaders(Headers headers, CaptureBuffer captureBuffer) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            String name = entry.getKey();
            List<String> values = entry.getValue();
            if (values == null || values.isEmpty()) {
                captureBuffer.appendLine(name + ":");
                continue;
            }
            for (String value : values) {
                captureBuffer.appendLine(name + ": " + nullToEmpty(value));
            }
        }
        captureBuffer.appendLine("");
    }

    private static Credentials extractBasicCredentials(Headers headers) {
        List<String> values = headers.get("Authorization");
        if (values == null || values.isEmpty()) {
            return null;
        }
        for (String value : values) {
            if (value == null) {
                continue;
            }
            String trimmed = value.trim();
            if (!trimmed.toLowerCase(Locale.ROOT).startsWith("basic ")) {
                continue;
            }
            String encoded = trimmed.substring(6).trim();
            String decoded = TcpCaptureUtil.decodeBase64Loose(encoded);
            if (decoded == null) {
                continue;
            }
            int separator = decoded.indexOf(':');
            if (separator >= 0) {
                return new Credentials(decoded.substring(0, separator), decoded.substring(separator + 1));
            }
            return new Credentials(decoded, null);
        }
        return null;
    }

    private static String host(InetSocketAddress address) {
        if (address == null) {
            return "";
        }
        InetAddress inetAddress = address.getAddress();
        if (inetAddress != null) {
            return inetAddress.getHostAddress();
        }
        String hostString = address.getHostString();
        return hostString == null ? "" : hostString;
    }

    private static int port(InetSocketAddress address) {
        if (address == null) {
            return 0;
        }
        return address.getPort();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, byte[] body) {
        try {
            Headers headers = exchange.getResponseHeaders();
            headers.set("Server", "DNSSinkspector");
            headers.set("Connection", "close");
            headers.set("Content-Type", "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(statusCode, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        } catch (IOException e) {
            // Connection may already be closed by the client; we still log the captured data.
        }
    }

    private static final class CaptureBuffer {
        private final int maxBytes;
        private final ByteArrayOutputStream payload;
        private boolean truncated;

        private CaptureBuffer(int maxBytes) {
            this.maxBytes = maxBytes;
            this.payload = new ByteArrayOutputStream(Math.min(maxBytes, 4096));
        }

        private void appendLine(String line) {
            byte[] bytes = (nullToEmpty(line) + "\n").getBytes(StandardCharsets.UTF_8);
            append(bytes, 0, bytes.length);
        }

        private void append(byte[] bytes, int offset, int length) {
            if (truncated || length <= 0) {
                return;
            }
            int remaining = maxBytes - payload.size();
            if (remaining <= 0) {
                truncated = true;
                return;
            }
            int toWrite = Math.min(length, remaining);
            payload.write(bytes, offset, toWrite);
            if (toWrite < length) {
                truncated = true;
            }
        }

        private boolean isTruncated() {
            return truncated;
        }

        private byte[] snapshot() {
            return payload.toByteArray();
        }
    }

    private record Credentials(String username, String password) {
    }
}
