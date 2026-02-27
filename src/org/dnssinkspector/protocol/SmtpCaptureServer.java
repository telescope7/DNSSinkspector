package org.dnssinkspector.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.commons.configuration2.BaseHierarchicalConfiguration;
import org.apache.commons.configuration2.Configuration;
import org.apache.james.core.MailAddress;
import org.apache.james.core.MaybeSender;
import org.apache.james.core.Username;
import org.apache.james.metrics.api.Metric;
import org.apache.james.metrics.api.MetricFactory;
import org.apache.james.metrics.api.TimeMetric;
import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.api.ProtocolSession.State;
import org.apache.james.protocols.api.Response;
import org.apache.james.protocols.api.handler.CommandDispatcher;
import org.apache.james.protocols.api.handler.ConnectHandler;
import org.apache.james.protocols.api.handler.DisconnectHandler;
import org.apache.james.protocols.api.handler.ProtocolHandler;
import org.apache.james.protocols.lib.handler.HandlersPackage;
import org.apache.james.protocols.lib.handler.ProtocolHandlerLoader;
import org.apache.james.protocols.smtp.MailEnvelope;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.core.DataCmdHandler;
import org.apache.james.protocols.smtp.core.DataLineMessageHookHandler;
import org.apache.james.protocols.smtp.core.HeloCmdHandler;
import org.apache.james.protocols.smtp.core.HelpCmdHandler;
import org.apache.james.protocols.smtp.core.MailCmdHandler;
import org.apache.james.protocols.smtp.core.NoopCmdHandler;
import org.apache.james.protocols.smtp.core.QuitCmdHandler;
import org.apache.james.protocols.smtp.core.RcptCmdHandler;
import org.apache.james.protocols.smtp.core.RsetCmdHandler;
import org.apache.james.protocols.smtp.core.UnknownCmdHandler;
import org.apache.james.protocols.smtp.core.WelcomeMessageHandler;
import org.apache.james.protocols.smtp.core.esmtp.AuthCmdHandler;
import org.apache.james.protocols.smtp.core.esmtp.EhloCmdHandler;
import org.apache.james.protocols.smtp.core.esmtp.MailSizeEsmtpExtension;
import org.apache.james.protocols.smtp.hook.AuthHook;
import org.apache.james.protocols.smtp.hook.HeloHook;
import org.apache.james.protocols.smtp.hook.HookResult;
import org.apache.james.protocols.smtp.hook.HookReturnCode;
import org.apache.james.protocols.smtp.hook.MailHook;
import org.apache.james.protocols.smtp.hook.MessageHook;
import org.apache.james.protocols.smtp.hook.QuitHook;
import org.apache.james.protocols.smtp.hook.RcptHook;
import org.apache.james.protocols.smtp.hook.UnknownHook;
import org.apache.james.smtpserver.netty.SMTPServer;
import org.apache.james.smtpserver.netty.SmtpMetricsImpl;
import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;
import org.reactivestreams.Publisher;

public final class SmtpCaptureServer implements CaptureService {
    private final TcpServiceConfig config;
    private final EventLogger eventLogger;
    private final AtomicLong sessionCounter = new AtomicLong(0);

    private SMTPServer smtpServer;

    public SmtpCaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        this.config = config;
        this.eventLogger = eventLogger;
    }

    @Override
    public synchronized void start() throws IOException {
        if (smtpServer != null && smtpServer.isStarted()) {
            return;
        }

        NoopMetricFactory metricFactory = new NoopMetricFactory();
        SmtpCaptureHook captureHook = new SmtpCaptureHook(config, eventLogger, sessionCounter);
        SMTPServer server = new SMTPServer(new SmtpMetricsImpl(metricFactory));
        server.setProtocolHandlerLoader(new SmtpProtocolHandlerLoader(metricFactory, captureHook));

        BaseHierarchicalConfiguration serverConfig = new BaseHierarchicalConfiguration();
        serverConfig.addProperty("[@enabled]", true);
        serverConfig.addProperty("bind", config.getListenAddress() + ":" + config.getListenPort());
        serverConfig.addProperty("connectiontimeout", Math.max(1, config.getReadTimeoutMs() / 1000));
        serverConfig.addProperty("smtpGreeting", "DNSSinkspector SMTP Service Ready");
        serverConfig.addProperty("heloEhloEnforcement", false);
        serverConfig.addProperty("auth.announce", "ALWAYS");
        serverConfig.addProperty("auth.plainAuthEnabled", true);
        serverConfig.addProperty("auth.requireSSL", false);
        serverConfig.addProperty("handlerchain[@enableJmx]", false);
        serverConfig.addProperty("handlerchain[@coreHandlersPackage]", SinkholeSmtpHandlersPackage.class.getName());
        serverConfig.addProperty("handlerchain[@jmxHandlersPackage]", SinkholeSmtpHandlersPackage.class.getName());

        try {
            server.configure(serverConfig);
            server.init();
            smtpServer = server;
        } catch (Exception e) {
            try {
                server.destroy();
            } catch (Exception destroyError) {
                System.err.println("Failed to destroy SMTP server after startup error: " + destroyError.getMessage());
            }
            throw new IOException("Failed to start SMTP listener: " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized void stop() {
        if (smtpServer == null) {
            return;
        }
        smtpServer.destroy();
        smtpServer = null;
    }

    @Override
    public String getProtocolName() {
        return "SMTP";
    }

    @Override
    public TcpServiceConfig getConfig() {
        return config;
    }

    public static final class SinkholeSmtpHandlersPackage implements HandlersPackage {
        private static final List<String> HANDLERS = List.of(
                WelcomeMessageHandler.class.getName(),
                CommandDispatcher.class.getName(),
                AuthCmdHandler.class.getName(),
                DataCmdHandler.class.getName(),
                EhloCmdHandler.class.getName(),
                HeloCmdHandler.class.getName(),
                HelpCmdHandler.class.getName(),
                MailCmdHandler.class.getName(),
                NoopCmdHandler.class.getName(),
                QuitCmdHandler.class.getName(),
                RcptCmdHandler.class.getName(),
                RsetCmdHandler.class.getName(),
                MailSizeEsmtpExtension.class.getName(),
                DataLineMessageHookHandler.class.getName(),
                UnknownCmdHandler.class.getName(),
                SmtpCaptureHook.class.getName());

        @Override
        public List<String> getHandlers() {
            return HANDLERS;
        }
    }

    private static final class SmtpProtocolHandlerLoader implements ProtocolHandlerLoader {
        private final MetricFactory metricFactory;
        private final SmtpCaptureHook captureHook;

        private SmtpProtocolHandlerLoader(MetricFactory metricFactory, SmtpCaptureHook captureHook) {
            this.metricFactory = metricFactory;
            this.captureHook = captureHook;
        }

        @Override
        public ProtocolHandler load(String className, Configuration configuration) throws LoadingException {
            try {
                ProtocolHandler handler = instantiate(className);
                handler.init(configuration);
                return handler;
            } catch (Exception e) {
                throw new LoadingException("Failed to load SMTP handler: " + className, e);
            }
        }

        private ProtocolHandler instantiate(String className) throws Exception {
            if (SinkholeSmtpHandlersPackage.class.getName().equals(className)) {
                return new SinkholeSmtpHandlersPackage();
            }
            if (SmtpCaptureHook.class.getName().equals(className)) {
                return captureHook;
            }

            Class<?> rawClass = Class.forName(className);
            if (!ProtocolHandler.class.isAssignableFrom(rawClass)) {
                throw new IllegalArgumentException("Class does not implement ProtocolHandler: " + className);
            }

            @SuppressWarnings("unchecked")
            Class<? extends ProtocolHandler> handlerClass = (Class<? extends ProtocolHandler>) rawClass;
            Constructor<? extends ProtocolHandler> metricFactoryCtor = findMetricFactoryConstructor(handlerClass);
            if (metricFactoryCtor != null) {
                return metricFactoryCtor.newInstance(metricFactory);
            }

            Constructor<? extends ProtocolHandler> noArgCtor = handlerClass.getDeclaredConstructor();
            noArgCtor.setAccessible(true);
            return noArgCtor.newInstance();
        }

        private static Constructor<? extends ProtocolHandler> findMetricFactoryConstructor(
                Class<? extends ProtocolHandler> handlerClass) {
            for (Constructor<?> ctor : handlerClass.getDeclaredConstructors()) {
                Class<?>[] parameters = ctor.getParameterTypes();
                if (parameters.length == 1 && MetricFactory.class.isAssignableFrom(parameters[0])) {
                    ctor.setAccessible(true);
                    @SuppressWarnings("unchecked")
                    Constructor<? extends ProtocolHandler> typedCtor = (Constructor<? extends ProtocolHandler>) ctor;
                    return typedCtor;
                }
            }
            return null;
        }
    }

    public static final class SmtpCaptureHook
            implements ConnectHandler<SMTPSession>,
            DisconnectHandler<SMTPSession>,
            HeloHook,
            MailHook,
            RcptHook,
            AuthHook,
            MessageHook,
            UnknownHook,
            QuitHook {
        private static final ProtocolSession.AttachmentKey<CaptureState> CAPTURE_STATE = ProtocolSession.AttachmentKey.of(
                "dnssinkspector.smtp.capture",
                CaptureState.class);

        private final TcpServiceConfig config;
        private final EventLogger eventLogger;
        private final AtomicLong sessionCounter;

        private SmtpCaptureHook(TcpServiceConfig config, EventLogger eventLogger, AtomicLong sessionCounter) {
            this.config = config;
            this.eventLogger = eventLogger;
            this.sessionCounter = sessionCounter;
        }

        @Override
        public Response onConnect(SMTPSession session) {
            CaptureState state = new CaptureState("SMTP-" + sessionCounter.incrementAndGet(), System.nanoTime());
            session.setAttachment(CAPTURE_STATE, state, State.Connection);
            return null;
        }

        @Override
        public void onDisconnect(SMTPSession session) {
            CaptureState state = stateFor(session);
            if (!state.markLogged()) {
                return;
            }

            byte[] payload = state.payloadSnapshot();
            long latencyMs = (System.nanoTime() - state.getStartedAtNanos()) / 1_000_000L;
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("timestamp_utc", Instant.now().toString());
            event.put("event_type", "tcp_session");
            event.put("protocol", "SMTP");
            event.put("transport", "tcp");
            event.put("client_ip", host(session.getRemoteAddress()));
            event.put("client_port", port(session.getRemoteAddress()));
            event.put("server_ip", host(session.getLocalAddress()));
            event.put("server_port", port(session.getLocalAddress()));
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
        }

        @Override
        public HookResult doHelo(SMTPSession session, String helo) {
            appendLine(stateFor(session), "HELO/EHLO " + nullToEmpty(helo));
            return HookResult.OK;
        }

        @Override
        public HookResult doMail(SMTPSession session, MaybeSender sender) {
            appendLine(stateFor(session), "MAIL FROM:<" + (sender == null ? "" : sender.asString()) + ">");
            return HookResult.OK;
        }

        @Override
        public HookResult doRcpt(SMTPSession session, MaybeSender sender, MailAddress recipient, Map<String, String> parameters) {
            String recipientValue = recipient == null ? "" : recipient.asString();
            appendLine(stateFor(session), "RCPT TO:<" + recipientValue + ">");
            return HookResult.OK;
        }

        @Override
        public HookResult doAuth(SMTPSession session, Username username, String password) {
            CaptureState state = stateFor(session);
            String usernameValue = username == null ? null : username.asString();
            state.setCredentials(usernameValue, password);
            appendLine(state, "AUTH USER " + nullToEmpty(usernameValue));
            if (password != null) {
                appendLine(state, "AUTH PASS " + password);
            }
            state.setDecision("captured_credentials_and_closed");
            return disconnectingOk("Authentication successful");
        }

        @Override
        public HookResult doSasl(SMTPSession session, org.apache.james.protocols.api.OidcSASLConfiguration configuration, String saslCommand) {
            appendLine(stateFor(session), "AUTH SASL " + nullToEmpty(saslCommand));
            return HookResult.DECLINED;
        }

        @Override
        public HookResult onMessage(SMTPSession session, MailEnvelope mailEnvelope) {
            CaptureState state = stateFor(session);
            appendLine(state, "DATA");
            try (InputStream in = mailEnvelope.getMessageInputStream()) {
                byte[] buffer = new byte[1024];
                while (true) {
                    int read = in.read(buffer);
                    if (read == -1) {
                        break;
                    }
                    state.append(buffer, 0, read, config.getCaptureMaxBytes());
                    if (state.isTruncated()) {
                        break;
                    }
                }
            } catch (IOException e) {
                state.setError("DATA capture error: " + e.getMessage());
                return HookResult.DENYSOFT;
            }
            state.setDecision("captured_message_and_closed");
            return disconnectingOk("Message accepted");
        }

        @Override
        public HookResult doUnknown(SMTPSession session, String line) {
            CaptureState state = stateFor(session);
            appendLine(state, "UNKNOWN " + nullToEmpty(line));
            state.setDecision("captured_unknown_and_closed");
            return disconnectingOk("Command captured");
        }

        @Override
        public HookResult doQuit(SMTPSession session) {
            appendLine(stateFor(session), "QUIT");
            return HookResult.OK;
        }

        private CaptureState stateFor(SMTPSession session) {
            Optional<CaptureState> existing = session.getAttachment(CAPTURE_STATE, State.Connection);
            if (existing.isPresent()) {
                return existing.get();
            }
            CaptureState created = new CaptureState("SMTP-" + sessionCounter.incrementAndGet(), System.nanoTime());
            session.setAttachment(CAPTURE_STATE, created, State.Connection);
            return created;
        }

        private void appendLine(CaptureState state, String line) {
            byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
            state.append(bytes, 0, bytes.length, config.getCaptureMaxBytes());
        }

        private static HookResult disconnectingOk(String description) {
            return HookResult.builder()
                    .hookReturnCode(HookReturnCode.disconnected(HookReturnCode.Action.OK))
                    .smtpDescription(description)
                    .build();
        }

        private static String nullToEmpty(String value) {
            return value == null ? "" : value;
        }

        private static String host(InetSocketAddress address) {
            if (address == null || address.getAddress() == null) {
                return "";
            }
            return address.getAddress().getHostAddress();
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
        private final ByteArrayOutputStream payload = new ByteArrayOutputStream();
        private final AtomicBoolean logged = new AtomicBoolean(false);

        private String username;
        private String password;
        private String decision;
        private String error;
        private boolean truncated;

        private CaptureState(String sessionId, long startedAtNanos) {
            this.sessionId = sessionId;
            this.startedAtNanos = startedAtNanos;
        }

        private synchronized void append(byte[] bytes, int offset, int length, int maxCaptureBytes) {
            if (length <= 0) {
                return;
            }

            int remaining = maxCaptureBytes - payload.size();
            if (remaining <= 0) {
                truncated = true;
                return;
            }

            int bytesToWrite = Math.min(remaining, length);
            payload.write(bytes, offset, bytesToWrite);
            if (bytesToWrite < length) {
                truncated = true;
            }
        }

        private synchronized void setCredentials(String username, String password) {
            this.username = username;
            this.password = password;
        }

        private synchronized void setDecision(String decision) {
            this.decision = decision;
        }

        private synchronized void setError(String error) {
            this.error = error;
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

    private static final class NoopMetricFactory implements MetricFactory {
        @Override
        public Metric generate(String name) {
            return new NoopMetric();
        }

        @Override
        public TimeMetric timer(String name) {
            return new NoopTimeMetric(name);
        }

        @Override
        public <T> Publisher<T> decoratePublisherWithTimerMetric(String name, Publisher<T> publisher) {
            return publisher;
        }

        @Override
        public <T> Publisher<T> decoratePublisherWithTimerMetricLogP99(String name, Publisher<T> publisher) {
            return publisher;
        }
    }

    private static final class NoopMetric implements Metric {
        private final AtomicLong value = new AtomicLong(0);

        @Override
        public void increment() {
            value.incrementAndGet();
        }

        @Override
        public void decrement() {
            value.decrementAndGet();
        }

        @Override
        public void add(int amount) {
            value.addAndGet(amount);
        }

        @Override
        public void remove(int amount) {
            value.addAndGet(-amount);
        }

        @Override
        public long getCount() {
            return value.get();
        }
    }

    private static final class NoopTimeMetric implements TimeMetric {
        private final String name;

        private NoopTimeMetric(String name) {
            this.name = name;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public ExecutionResult stopAndPublish() {
            return new NoopExecutionResult();
        }

        @Override
        public void record(Duration duration) {
            // no-op
        }
    }

    private static final class NoopExecutionResult implements TimeMetric.ExecutionResult {
        @Override
        public Duration elasped() {
            return Duration.ZERO;
        }

        @Override
        public TimeMetric.ExecutionResult logWhenExceedP99(Duration duration) {
            return this;
        }
    }
}
