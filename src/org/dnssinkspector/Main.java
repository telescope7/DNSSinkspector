package org.dnssinkspector;

import java.io.IOException;
import java.net.SocketException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.dnssinkspector.config.SinkholeConfig;
import org.dnssinkspector.config.TomlConfigLoader;
import org.dnssinkspector.dns.DnsServer;
import org.dnssinkspector.logging.CompositeEventLogger;
import org.dnssinkspector.logging.EventLogger;
import org.dnssinkspector.logging.JsonlEventLogger;
import org.dnssinkspector.logging.SanitizingEventLogger;
import org.dnssinkspector.logging.TsvEventLogger;
import org.dnssinkspector.protocol.AbstractTcpCaptureServer;
import org.dnssinkspector.protocol.FtpCaptureServer;
import org.dnssinkspector.protocol.HttpCaptureServer;
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
            EventLogger eventLogger = new CompositeEventLogger(List.of(
                    new JsonlEventLogger(config.getJsonLogPath()),
                    new TsvEventLogger(config.getTsvLogPath()),
                    new SanitizingEventLogger(
                            new JsonlEventLogger(config.getCleanJsonLogPath()),
                            sanitizedExcludedFields),
                    new TsvEventLogger(config.getCleanTsvLogPath(), sanitizedExcludedFields)));
            DnsServer dnsServer = new DnsServer(config, eventLogger);
            List<AbstractTcpCaptureServer> tcpServers = new ArrayList<>();

            if (config.getHttpConfig().isEnabled()) {
                tcpServers.add(new HttpCaptureServer(config.getHttpConfig(), eventLogger));
            }
            if (config.getSmtpConfig().isEnabled()) {
                tcpServers.add(new SmtpCaptureServer(config.getSmtpConfig(), eventLogger));
            }
            if (config.getFtpConfig().isEnabled()) {
                tcpServers.add(new FtpCaptureServer(config.getFtpConfig(), eventLogger));
            }

            try {
                for (AbstractTcpCaptureServer tcpServer : tcpServers) {
                    tcpServer.start();
                    System.out.printf(
                            "Starting %s listener on %s:%d%n",
                            tcpServer.getProtocolName(),
                            tcpServer.getConfig().getListenAddress(),
                            tcpServer.getConfig().getListenPort());
                }
            } catch (IOException e) {
                for (AbstractTcpCaptureServer tcpServer : tcpServers) {
                    tcpServer.stop();
                }
                eventLogger.close();
                throw e;
            }

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                dnsServer.stop();
                for (AbstractTcpCaptureServer tcpServer : tcpServers) {
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
        System.out.println("  java -cp bin org.dnssinkspector.Main [--config <path>] [--help]");
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
