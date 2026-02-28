package org.dnssinkspector;

import java.io.IOException;
import java.net.SocketException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.dnssinkspector.config.SinkholeConfig;
import org.dnssinkspector.config.TomlConfigLoader;
import org.dnssinkspector.dns.DnsServer;
import org.dnssinkspector.logging.AsnEnrichingEventLogger;
import org.dnssinkspector.logging.CompositeEventLogger;
import org.dnssinkspector.logging.EventLogger;
import org.dnssinkspector.logging.JsonlEventLogger;
import org.dnssinkspector.logging.SanitizingEventLogger;
import org.dnssinkspector.logging.TsvEventLogger;
import org.dnssinkspector.protocol.BinaryCaptureServer;
import org.dnssinkspector.protocol.CaptureService;
import org.dnssinkspector.protocol.FtpCaptureServer;
import org.dnssinkspector.protocol.HttpCaptureServer;
import org.dnssinkspector.protocol.ImapCaptureServer;
import org.dnssinkspector.protocol.LdapCaptureServer;
import org.dnssinkspector.protocol.Pop3CaptureServer;
import org.dnssinkspector.protocol.SmbCaptureServer;
import org.dnssinkspector.protocol.SmtpCaptureServer;

public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        try {
            CliOptions options = CliOptions.parse(args);
            if (options.showHelp) {
                printUsage();
                return;
            }

            SinkholeConfig config = TomlConfigLoader.load(options.configPath);
            Set<String> sanitizedExcludedFields = Set.of("data_text", "data_base64");
            EventLogger baseLogger = new CompositeEventLogger(List.of(
                    new JsonlEventLogger(config.getJsonLogPath()),
                    new TsvEventLogger(config.getTsvLogPath()),
                    new SanitizingEventLogger(
                            new JsonlEventLogger(config.getCleanJsonLogPath()),
                            sanitizedExcludedFields),
                    new TsvEventLogger(config.getCleanTsvLogPath(), sanitizedExcludedFields)));
            Optional<Path> maxmindAsnDbPath = config.getMaxmindAsnDbPath();
            EventLogger eventLogger = maxmindAsnDbPath.isPresent()
                    ? new AsnEnrichingEventLogger(baseLogger, maxmindAsnDbPath.get())
                    : baseLogger;
            DnsServer dnsServer = new DnsServer(config, eventLogger);
            List<CaptureService> tcpServers = new ArrayList<>();

            if (config.getHttpConfig().isEnabled()) {
                tcpServers.add(new HttpCaptureServer(config.getHttpConfig(), eventLogger));
            }
            if (config.getSmtpConfig().isEnabled()) {
                tcpServers.add(new SmtpCaptureServer(
                        config.getSmtpConfig(),
                        eventLogger,
                        config.getSmtpMessageDir()));
            }
            if (config.getFtpConfig().isEnabled()) {
                tcpServers.add(new FtpCaptureServer(config.getFtpConfig(), eventLogger));
            }
            if (config.getImapConfig().isEnabled()) {
                tcpServers.add(new ImapCaptureServer(config.getImapConfig(), eventLogger));
            }
            if (config.getImapsConfig().isEnabled()) {
                tcpServers.add(new BinaryCaptureServer("IMAPS", config.getImapsConfig(), eventLogger, null));
            }
            if (config.getPop3Config().isEnabled()) {
                tcpServers.add(new Pop3CaptureServer(config.getPop3Config(), eventLogger));
            }
            if (config.getPop3sConfig().isEnabled()) {
                tcpServers.add(new BinaryCaptureServer("POP3S", config.getPop3sConfig(), eventLogger, null));
            }
            if (config.getSshConfig().isEnabled()) {
                tcpServers.add(new BinaryCaptureServer(
                        "SSH",
                        config.getSshConfig(),
                        eventLogger,
                        "SSH-2.0-OpenSSH_9.0 DNSSinkspector\r\n"));
            }
            if (config.getLdapConfig().isEnabled()) {
                tcpServers.add(new LdapCaptureServer(config.getLdapConfig(), eventLogger));
            }
            if (config.getLdapsConfig().isEnabled()) {
                tcpServers.add(new BinaryCaptureServer("LDAPS", config.getLdapsConfig(), eventLogger, null));
            }
            if (config.getKerberosConfig().isEnabled()) {
                tcpServers.add(new BinaryCaptureServer("KERBEROS", config.getKerberosConfig(), eventLogger, null));
            }
            if (config.getSmbConfig().isEnabled()) {
                tcpServers.add(new SmbCaptureServer(config.getSmbConfig(), eventLogger));
            }
            if (config.getRdpConfig().isEnabled()) {
                tcpServers.add(new BinaryCaptureServer("RDP", config.getRdpConfig(), eventLogger, null));
            }
            if (config.getRpcConfig().isEnabled()) {
                tcpServers.add(new BinaryCaptureServer("MSRPC", config.getRpcConfig(), eventLogger, null));
            }
            if (config.getNetbiosConfig().isEnabled()) {
                tcpServers.add(new BinaryCaptureServer("NETBIOS-SSN", config.getNetbiosConfig(), eventLogger, null));
            }
            if (config.getWinrmHttpConfig().isEnabled()) {
                tcpServers.add(new HttpCaptureServer(
                        config.getWinrmHttpConfig(),
                        eventLogger,
                        "WINRM-HTTP"));
            }
            if (config.getWinrmHttpsConfig().isEnabled()) {
                tcpServers.add(new HttpCaptureServer(
                        config.getWinrmHttpsConfig(),
                        eventLogger,
                        "WINRM-HTTPS"));
            }

            try {
                for (CaptureService tcpServer : tcpServers) {
                    tcpServer.start();
                    System.out.printf(
                            "Starting %s listener on %s:%d%n",
                            tcpServer.getProtocolName(),
                            tcpServer.getConfig().getListenAddress(),
                            tcpServer.getConfig().getListenPort());
                }
            } catch (IOException e) {
                for (CaptureService tcpServer : tcpServers) {
                    tcpServer.stop();
                }
                eventLogger.close();
                throw e;
            }

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                dnsServer.stop();
                for (CaptureService tcpServer : tcpServers) {
                    tcpServer.stop();
                }
                try {
                    eventLogger.close();
                } catch (IOException e) {
                    System.err.println("Failed to close event logger: " + e.getMessage());
                }
            }));

            System.out.printf("Starting DNSSinkspector on %s:%d%n",
                    config.getListenAddress(), config.getListenPort());
            System.out.printf("Full JSONL log file: %s%n", config.getJsonLogPath().toAbsolutePath());
            System.out.printf("Full TSV log file: %s%n", config.getTsvLogPath().toAbsolutePath());
            System.out.printf("Clean JSONL log file: %s%n", config.getCleanJsonLogPath().toAbsolutePath());
            System.out.printf("Clean TSV log file: %s%n", config.getCleanTsvLogPath().toAbsolutePath());
            if (config.getSmtpConfig().isEnabled()) {
                System.out.printf("SMTP message directory: %s%n", config.getSmtpMessageDir().toAbsolutePath());
            }
            if (maxmindAsnDbPath.isPresent()) {
                System.out.printf("MaxMind ASN DB: %s%n", maxmindAsnDbPath.get().toAbsolutePath());
            }
            dnsServer.start();
        } catch (IllegalArgumentException e) {
            System.err.println("Argument error: " + e.getMessage());
            printUsage();
            System.exit(2);
        } catch (SocketException e) {
            System.err.println("Unable to open network socket: " + e.getMessage());
            System.exit(3);
        } catch (IOException e) {
            System.err.println("Failed to start service: " + e.getMessage());
            System.exit(4);
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  java -jar dnssinkspector-<version>.jar [--config <path>] [--help]");
        System.out.println("  ./bin/run.sh [--config <path>] [--help]");
        System.out.println();
        System.out.println("Defaults:");
        System.out.println("  --config config/sinkhole.toml");
    }

    private static final class CliOptions {
        private final boolean showHelp;
        private final Path configPath;

        private CliOptions(boolean showHelp, Path configPath) {
            this.showHelp = showHelp;
            this.configPath = configPath;
        }

        private static CliOptions parse(String[] args) {
            boolean showHelp = false;
            Path configPath = Paths.get("config", "sinkhole.toml");

            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if ("--help".equals(arg) || "-h".equals(arg)) {
                    showHelp = true;
                    continue;
                }
                if ("--config".equals(arg)) {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--config requires a value");
                    }
                    configPath = Paths.get(args[++i]);
                    continue;
                }
                throw new IllegalArgumentException("Unknown argument: " + arg);
            }

            return new CliOptions(showHelp, configPath);
        }
    }
}
