package org.dnssinkspector.config;

import java.net.Inet4Address;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class SinkholeConfig {
    public enum DefaultResponseMode {
        NXDOMAIN,
        NODATA
    }

    public static final class Zone {
        private final String domain;
        private final List<Inet4Address> answerIpv4;
        private final int ttlSeconds;
        private final List<String> tags;

        public Zone(String domain, List<Inet4Address> answerIpv4, int ttlSeconds, List<String> tags) {
            this.domain = normalizeDomain(domain);
            this.answerIpv4 = List.copyOf(answerIpv4);
            this.ttlSeconds = ttlSeconds;
            this.tags = List.copyOf(tags);
        }

        public String getDomain() {
            return domain;
        }

        public List<Inet4Address> getAnswerIpv4() {
            return answerIpv4;
        }

        public int getTtlSeconds() {
            return ttlSeconds;
        }

        public List<String> getTags() {
            return tags;
        }
    }

    public static final class TcpServiceConfig {
        private final boolean enabled;
        private final String listenAddress;
        private final int listenPort;
        private final int readTimeoutMs;
        private final int captureMaxBytes;
        private final boolean tlsEnabled;
        private final String tlsKeystorePath;
        private final String tlsKeystorePassword;
        private final String tlsKeyPassword;
        private final String tlsKeystoreType;

        public TcpServiceConfig(
                boolean enabled,
                String listenAddress,
                int listenPort,
                int readTimeoutMs,
                int captureMaxBytes,
                boolean tlsEnabled,
                String tlsKeystorePath,
                String tlsKeystorePassword,
                String tlsKeyPassword,
                String tlsKeystoreType) {
            this.enabled = enabled;
            this.listenAddress = listenAddress;
            this.listenPort = listenPort;
            this.readTimeoutMs = readTimeoutMs;
            this.captureMaxBytes = captureMaxBytes;
            this.tlsEnabled = tlsEnabled;
            this.tlsKeystorePath = tlsKeystorePath == null ? "" : tlsKeystorePath;
            this.tlsKeystorePassword = tlsKeystorePassword == null ? "" : tlsKeystorePassword;
            this.tlsKeyPassword = tlsKeyPassword == null ? "" : tlsKeyPassword;
            this.tlsKeystoreType = tlsKeystoreType == null ? "PKCS12" : tlsKeystoreType;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public String getListenAddress() {
            return listenAddress;
        }

        public int getListenPort() {
            return listenPort;
        }

        public int getReadTimeoutMs() {
            return readTimeoutMs;
        }

        public int getCaptureMaxBytes() {
            return captureMaxBytes;
        }

        public boolean isTlsEnabled() {
            return tlsEnabled;
        }

        public String getTlsKeystorePath() {
            return tlsKeystorePath;
        }

        public String getTlsKeystorePassword() {
            return tlsKeystorePassword;
        }

        public String getTlsKeyPassword() {
            return tlsKeyPassword;
        }

        public String getTlsKeystoreType() {
            return tlsKeystoreType;
        }
    }

    private final String listenAddress;
    private final int listenPort;
    private final boolean authoritative;
    private final DefaultResponseMode defaultResponseMode;
    private final Path jsonLogPath;
    private final Path tsvLogPath;
    private final Path cleanJsonLogPath;
    private final Path cleanTsvLogPath;
    private final Path maxmindAsnDbPath;
    private final TcpServiceConfig httpConfig;
    private final TcpServiceConfig smtpConfig;
    private final TcpServiceConfig ftpConfig;
    private final Map<String, Zone> zonesByDomain;

    public SinkholeConfig(
            String listenAddress,
            int listenPort,
            boolean authoritative,
            DefaultResponseMode defaultResponseMode,
            Path jsonLogPath,
            Path tsvLogPath,
            Path cleanJsonLogPath,
            Path cleanTsvLogPath,
            Path maxmindAsnDbPath,
            TcpServiceConfig httpConfig,
            TcpServiceConfig smtpConfig,
            TcpServiceConfig ftpConfig,
            List<Zone> zones) {
        this.listenAddress = listenAddress;
        this.listenPort = listenPort;
        this.authoritative = authoritative;
        this.defaultResponseMode = defaultResponseMode;
        this.jsonLogPath = jsonLogPath;
        this.tsvLogPath = tsvLogPath;
        this.cleanJsonLogPath = cleanJsonLogPath;
        this.cleanTsvLogPath = cleanTsvLogPath;
        this.maxmindAsnDbPath = maxmindAsnDbPath;
        this.httpConfig = httpConfig;
        this.smtpConfig = smtpConfig;
        this.ftpConfig = ftpConfig;

        Map<String, Zone> zoneMap = new HashMap<>();
        for (Zone zone : zones) {
            zoneMap.put(zone.getDomain(), zone);
        }
        this.zonesByDomain = Collections.unmodifiableMap(zoneMap);
    }

    public String getListenAddress() {
        return listenAddress;
    }

    public int getListenPort() {
        return listenPort;
    }

    public boolean isAuthoritative() {
        return authoritative;
    }

    public DefaultResponseMode getDefaultResponseMode() {
        return defaultResponseMode;
    }

    public Path getJsonLogPath() {
        return jsonLogPath;
    }

    public Path getTsvLogPath() {
        return tsvLogPath;
    }

    public Path getCleanJsonLogPath() {
        return cleanJsonLogPath;
    }

    public Path getCleanTsvLogPath() {
        return cleanTsvLogPath;
    }

    public Optional<Path> getMaxmindAsnDbPath() {
        return Optional.ofNullable(maxmindAsnDbPath);
    }

    public TcpServiceConfig getHttpConfig() {
        return httpConfig;
    }

    public TcpServiceConfig getSmtpConfig() {
        return smtpConfig;
    }

    public TcpServiceConfig getFtpConfig() {
        return ftpConfig;
    }

    public Map<String, Zone> getZonesByDomain() {
        return zonesByDomain;
    }

    public Optional<Zone> findZone(String domainName) {
        String normalized = normalizeDomain(domainName);
        Zone exact = zonesByDomain.get(normalized);
        if (exact != null) {
            return Optional.of(exact);
        }
        Zone bestMatch = null;
        int bestLength = -1;
        for (Map.Entry<String, Zone> entry : zonesByDomain.entrySet()) {
            String zoneDomain = entry.getKey();
            if (normalized.endsWith("." + zoneDomain) && zoneDomain.length() > bestLength) {
                bestMatch = entry.getValue();
                bestLength = zoneDomain.length();
            }
        }
        return Optional.ofNullable(bestMatch);
    }

    public static String normalizeDomain(String raw) {
        String trimmed = raw == null ? "" : raw.trim();
        if (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed.toLowerCase(Locale.ROOT);
    }
}
