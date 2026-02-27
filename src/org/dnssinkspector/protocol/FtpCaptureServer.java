package org.dnssinkspector.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.ftpserver.FtpServer;
import org.apache.ftpserver.FtpServerFactory;
import org.apache.ftpserver.ftplet.DefaultFtpReply;
import org.apache.ftpserver.ftplet.DefaultFtplet;
import org.apache.ftpserver.ftplet.FtpException;
import org.apache.ftpserver.ftplet.FtpReply;
import org.apache.ftpserver.ftplet.FtpRequest;
import org.apache.ftpserver.ftplet.FtpSession;
import org.apache.ftpserver.ftplet.FtpletResult;
import org.apache.ftpserver.listener.ListenerFactory;
import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;

public final class FtpCaptureServer implements CaptureService {
    private final TcpServiceConfig config;
    private final EventLogger eventLogger;
    private final AtomicLong sessionCounter = new AtomicLong(0);

    private FtpServer ftpServer;

    public FtpCaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        this.config = config;
        this.eventLogger = eventLogger;
    }

    @Override
    public synchronized void start() throws IOException {
        if (ftpServer != null && !ftpServer.isStopped()) {
            return;
        }

        FtpServerFactory factory = new FtpServerFactory();
        ListenerFactory listenerFactory = new ListenerFactory();
        listenerFactory.setServerAddress(config.getListenAddress());
        listenerFactory.setPort(config.getListenPort());
        listenerFactory.setIdleTimeout(Math.max(1, config.getReadTimeoutMs() / 1000));
        factory.addListener("default", listenerFactory.createListener());
        Map<String, org.apache.ftpserver.ftplet.Ftplet> ftplets = new LinkedHashMap<>();
        ftplets.put("capture", new FtpCaptureFtplet(config, eventLogger, sessionCounter));
        factory.setFtplets(ftplets);

        FtpServer server = factory.createServer();
        try {
            server.start();
            ftpServer = server;
        } catch (FtpException e) {
            server.stop();
            throw new IOException("Failed to start FTP listener: " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized void stop() {
        if (ftpServer == null) {
            return;
        }
        ftpServer.stop();
        ftpServer = null;
    }

    @Override
    public String getProtocolName() {
        return "FTP";
    }

    @Override
    public TcpServiceConfig getConfig() {
        return config;
    }

    private static final class FtpCaptureFtplet extends DefaultFtplet {
        private static final String STATE_KEY = "dnssinkspector.ftp.capture";

        private final TcpServiceConfig config;
        private final EventLogger eventLogger;
        private final AtomicLong sessionCounter;

        private FtpCaptureFtplet(TcpServiceConfig config, EventLogger eventLogger, AtomicLong sessionCounter) {
            this.config = config;
            this.eventLogger = eventLogger;
            this.sessionCounter = sessionCounter;
        }

        @Override
        public FtpletResult onConnect(FtpSession session) {
            CaptureState state = new CaptureState("FTP-" + sessionCounter.incrementAndGet(), System.nanoTime());
            session.setAttribute(STATE_KEY, state);
            return FtpletResult.DEFAULT;
        }

        @Override
        public FtpletResult beforeCommand(FtpSession session, FtpRequest request) throws FtpException {
            CaptureState state = stateFor(session);
            state.appendLine(request.getRequestLine(), config.getCaptureMaxBytes());
            String command = request.getCommand() == null ? "" : request.getCommand().trim().toUpperCase(Locale.ROOT);
            String argument = request.getArgument();

            if ("USER".equals(command)) {
                state.setUsername(argument);
                return FtpletResult.DEFAULT;
            }

            if ("PASS".equals(command)) {
                state.setPassword(argument);
                state.setDecision("captured_credentials_and_closed");
                session.write(new DefaultFtpReply(230, "User logged in"));
                return FtpletResult.DISCONNECT;
            }

            if (state.isTruncated()) {
                state.setDecision("captured_truncated_and_closed");
                session.write(new DefaultFtpReply(421, "Capture limit reached, closing control connection"));
                return FtpletResult.DISCONNECT;
            }

            return FtpletResult.DEFAULT;
        }

        @Override
        public FtpletResult afterCommand(FtpSession session, FtpRequest request, FtpReply reply) {
            CaptureState state = stateFor(session);
            String command = request.getCommand() == null ? "" : request.getCommand().trim().toUpperCase(Locale.ROOT);
            if ("QUIT".equals(command)) {
                state.setDecision("captured_and_closed");
            }
            return FtpletResult.DEFAULT;
        }

        @Override
        public FtpletResult onDisconnect(FtpSession session) {
            CaptureState state = stateFor(session);
            if (!state.markLogged()) {
                return FtpletResult.DEFAULT;
            }

            byte[] payload = state.payloadSnapshot();
            long latencyMs = (System.nanoTime() - state.getStartedAtNanos()) / 1_000_000L;
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("timestamp_utc", Instant.now().toString());
            event.put("event_type", "tcp_session");
            event.put("protocol", "FTP");
            event.put("transport", "tcp");
            event.put("client_ip", host(session.getClientAddress()));
            event.put("client_port", port(session.getClientAddress()));
            event.put("server_ip", host(session.getServerAddress()));
            event.put("server_port", port(session.getServerAddress()));
            event.put("session_id", state.getSessionId());
            event.put("decision", state.resolveDecision());
            event.put("username", state.getUsername());
            event.put("password", state.getPassword());
            event.put("data_text", new String(payload, StandardCharsets.UTF_8));
            event.put("data_base64", Base64.getEncoder().encodeToString(payload));
            event.put("request_size_bytes", payload.length);
            event.put("truncated", state.isTruncated());
            event.put("error", state.getError());
            event.put("latency_ms", latencyMs);
            eventLogger.logEvent(event);
            return FtpletResult.DEFAULT;
        }

        private CaptureState stateFor(FtpSession session) {
            Object state = session.getAttribute(STATE_KEY);
            if (state instanceof CaptureState) {
                return (CaptureState) state;
            }
            CaptureState created = new CaptureState("FTP-" + sessionCounter.incrementAndGet(), System.nanoTime());
            session.setAttribute(STATE_KEY, created);
            return created;
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
    }

    private static final class CaptureState {
        private final String sessionId;
        private final long startedAtNanos;
        private final AtomicBoolean logged = new AtomicBoolean(false);
        private final ByteArrayOutputStream payload = new ByteArrayOutputStream();

        private String username;
        private String password;
        private String decision;
        private String error;
        private boolean truncated;

        private CaptureState(String sessionId, long startedAtNanos) {
            this.sessionId = sessionId;
            this.startedAtNanos = startedAtNanos;
        }

        private synchronized void appendLine(String line, int maxCaptureBytes) {
            if (line == null) {
                return;
            }
            byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
            int remaining = maxCaptureBytes - payload.size();
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

        private synchronized void setUsername(String username) {
            this.username = username;
        }

        private synchronized void setPassword(String password) {
            this.password = password;
        }

        private synchronized void setDecision(String decision) {
            this.decision = decision;
        }

        private synchronized String resolveDecision() {
            if (error != null) {
                return "capture_error";
            }
            if (decision != null && !decision.isBlank()) {
                return decision;
            }
            if (truncated) {
                return "captured_truncated_and_closed";
            }
            return "captured_and_closed";
        }

        private synchronized byte[] payloadSnapshot() {
            return payload.toByteArray();
        }

        private synchronized boolean isTruncated() {
            return truncated;
        }

        private synchronized String getUsername() {
            return username;
        }

        private synchronized String getPassword() {
            return password;
        }

        private synchronized String getError() {
            return error;
        }

        private String getSessionId() {
            return sessionId;
        }

        private long getStartedAtNanos() {
            return startedAtNanos;
        }

        private boolean markLogged() {
            return logged.compareAndSet(false, true);
        }
    }
}
