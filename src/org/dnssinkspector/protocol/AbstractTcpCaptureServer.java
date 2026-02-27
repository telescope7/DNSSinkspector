package org.dnssinkspector.protocol;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;

public abstract class AbstractTcpCaptureServer implements CaptureService {
    private final String protocolName;
    private final TcpServiceConfig config;
    private final EventLogger eventLogger;
    private final AtomicLong sessionCounter = new AtomicLong(0);

    private volatile boolean running;
    private ServerSocket serverSocket;
    private Thread acceptThread;
    private ExecutorService connectionExecutor;

    protected AbstractTcpCaptureServer(String protocolName, TcpServiceConfig config, EventLogger eventLogger) {
        this.protocolName = protocolName;
        this.config = config;
        this.eventLogger = eventLogger;
    }

    @Override
    public synchronized void start() throws IOException {
        if (running) {
            return;
        }
        serverSocket = new ServerSocket();
        serverSocket.bind(new InetSocketAddress(config.getListenAddress(), config.getListenPort()));
        connectionExecutor = Executors.newCachedThreadPool();
        running = true;

        acceptThread = new Thread(this::acceptLoop, protocolName.toLowerCase() + "-acceptor");
        acceptThread.start();
    }

    @Override
    public synchronized void stop() {
        running = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                System.err.printf("%s listener close failed: %s%n", protocolName, e.getMessage());
            }
        }

        if (connectionExecutor != null) {
            connectionExecutor.shutdownNow();
            try {
                connectionExecutor.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        if (acceptThread != null) {
            try {
                acceptThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
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

    private void acceptLoop() {
        while (running) {
            Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                if (running) {
                    System.err.printf("%s accept failed: %s%n", protocolName, e.getMessage());
                }
                break;
            }

            connectionExecutor.submit(() -> handleConnection(socket));
        }
    }

    private void handleConnection(Socket socket) {
        long startedAtNanos = System.nanoTime();
        String sessionId = protocolName + "-" + sessionCounter.incrementAndGet();
        String clientIp = socket.getInetAddress().getHostAddress();
        int clientPort = socket.getPort();
        String serverIp = socket.getLocalAddress().getHostAddress();
        int serverPort = socket.getLocalPort();
        TcpSessionCapture capture = null;
        try (Socket client = socket) {
            client.setSoTimeout(config.getReadTimeoutMs());
            capture = captureSession(client);
        } catch (Exception e) {
            capture = new TcpSessionCapture(
                    null,
                    null,
                    null,
                    null,
                    0,
                    false,
                    "capture_error",
                    e.getMessage());
        } finally {
            logSession(clientIp, clientPort, serverIp, serverPort, capture, sessionId, startedAtNanos);
        }
    }

    private void logSession(
            String clientIp,
            int clientPort,
            String serverIp,
            int serverPort,
            TcpSessionCapture capture,
            String sessionId,
            long startedAtNanos) {
        long latencyMs = (System.nanoTime() - startedAtNanos) / 1_000_000L;
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("timestamp_utc", Instant.now().toString());
        event.put("event_type", "tcp_session");
        event.put("protocol", protocolName);
        event.put("transport", "tcp");
        event.put("client_ip", clientIp);
        event.put("client_port", clientPort);
        event.put("server_ip", serverIp);
        event.put("server_port", serverPort);
        event.put("session_id", sessionId);
        event.put("decision", capture == null ? "capture_error" : capture.getDecision());
        event.put("username", capture == null ? null : capture.getUsername());
        event.put("password", capture == null ? null : capture.getPassword());
        event.put("data_text", capture == null ? null : capture.getDataText());
        event.put("data_base64", capture == null ? null : capture.getDataBase64());
        event.put("request_size_bytes", capture == null ? 0 : capture.getBytesCaptured());
        event.put("truncated", capture != null && capture.isTruncated());
        event.put("error", capture == null ? "No capture result" : capture.getError());
        event.put("latency_ms", latencyMs);
        eventLogger.logEvent(event);
    }

    protected abstract TcpSessionCapture captureSession(Socket socket) throws IOException;
}
