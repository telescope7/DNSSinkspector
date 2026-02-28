package org.dnssinkspector.config;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.dnssinkspector.config.SinkholeConfig.DefaultResponseMode;
import org.dnssinkspector.config.SinkholeConfig.Zone;

public final class TomlConfigLoader {

    private TomlConfigLoader() {
    }

    public static SinkholeConfig load(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);

        Map<String, Object> serverTable = new HashMap<>();
        Map<String, Object> httpTable = new HashMap<>();
        Map<String, Object> smtpTable = new HashMap<>();
        Map<String, Object> ftpTable = new HashMap<>();
        Map<String, Object> imapTable = new HashMap<>();
        Map<String, Object> imapsTable = new HashMap<>();
        Map<String, Object> pop3Table = new HashMap<>();
        Map<String, Object> pop3sTable = new HashMap<>();
        Map<String, Object> sshTable = new HashMap<>();
        Map<String, Object> ldapTable = new HashMap<>();
        Map<String, Object> ldapsTable = new HashMap<>();
        Map<String, Object> kerberosTable = new HashMap<>();
        Map<String, Object> smbTable = new HashMap<>();
        Map<String, Object> rdpTable = new HashMap<>();
        Map<String, Object> rpcTable = new HashMap<>();
        Map<String, Object> netbiosTable = new HashMap<>();
        Map<String, Object> winrmHttpTable = new HashMap<>();
        Map<String, Object> winrmHttpsTable = new HashMap<>();
        List<Map<String, Object>> zoneTables = new ArrayList<>();
        Map<String, Object> activeTable = new HashMap<>();
        String activeTableName = "";

        for (int lineNo = 1; lineNo <= lines.size(); lineNo++) {
            String rawLine = lines.get(lineNo - 1);
            String line = stripComments(rawLine).trim();
            if (line.isEmpty()) {
                continue;
            }

            if (line.startsWith("[[") && line.endsWith("]]")) {
                String tableName = line.substring(2, line.length() - 2).trim();
                if (!"zones".equals(tableName)) {
                    throw new IllegalArgumentException("Unsupported table at line " + lineNo + ": " + tableName);
                }
                Map<String, Object> zoneTable = new HashMap<>();
                zoneTables.add(zoneTable);
                activeTable = zoneTable;
                activeTableName = "zones";
                continue;
            }

            if (line.startsWith("[") && line.endsWith("]")) {
                String tableName = line.substring(1, line.length() - 1).trim();
                if ("server".equals(tableName)) {
                    activeTable = serverTable;
                    activeTableName = "server";
                } else if ("http".equals(tableName)) {
                    activeTable = httpTable;
                    activeTableName = "http";
                } else if ("smtp".equals(tableName)) {
                    activeTable = smtpTable;
                    activeTableName = "smtp";
                } else if ("ftp".equals(tableName)) {
                    activeTable = ftpTable;
                    activeTableName = "ftp";
                } else if ("imap".equals(tableName)) {
                    activeTable = imapTable;
                    activeTableName = "imap";
                } else if ("imaps".equals(tableName)) {
                    activeTable = imapsTable;
                    activeTableName = "imaps";
                } else if ("pop3".equals(tableName)) {
                    activeTable = pop3Table;
                    activeTableName = "pop3";
                } else if ("pop3s".equals(tableName)) {
                    activeTable = pop3sTable;
                    activeTableName = "pop3s";
                } else if ("ssh".equals(tableName)) {
                    activeTable = sshTable;
                    activeTableName = "ssh";
                } else if ("ldap".equals(tableName)) {
                    activeTable = ldapTable;
                    activeTableName = "ldap";
                } else if ("ldaps".equals(tableName)) {
                    activeTable = ldapsTable;
                    activeTableName = "ldaps";
                } else if ("kerberos".equals(tableName)) {
                    activeTable = kerberosTable;
                    activeTableName = "kerberos";
                } else if ("smb".equals(tableName)) {
                    activeTable = smbTable;
                    activeTableName = "smb";
                } else if ("rdp".equals(tableName)) {
                    activeTable = rdpTable;
                    activeTableName = "rdp";
                } else if ("rpc".equals(tableName)) {
                    activeTable = rpcTable;
                    activeTableName = "rpc";
                } else if ("netbios".equals(tableName)) {
                    activeTable = netbiosTable;
                    activeTableName = "netbios";
                } else if ("winrm_http".equals(tableName)) {
                    activeTable = winrmHttpTable;
                    activeTableName = "winrm_http";
                } else if ("winrm_https".equals(tableName)) {
                    activeTable = winrmHttpsTable;
                    activeTableName = "winrm_https";
                } else {
                    throw new IllegalArgumentException("Unsupported table at line " + lineNo + ": " + tableName);
                }
                continue;
            }

            int separator = line.indexOf('=');
            if (separator < 1) {
                throw new IllegalArgumentException("Invalid key/value syntax at line " + lineNo);
            }
            if (activeTableName.isEmpty()) {
                throw new IllegalArgumentException("Key/value outside a table at line " + lineNo);
            }

            String key = line.substring(0, separator).trim();
            String valueText = line.substring(separator + 1).trim();
            if (key.isEmpty()) {
                throw new IllegalArgumentException("Empty key at line " + lineNo);
            }

            Object value = parseValue(valueText, lineNo);
            activeTable.put(key, value);
        }

        String listenAddress = getString(serverTable, "listen_address", "0.0.0.0");
        int listenPort = getInt(serverTable, "listen_port", 5300);
        boolean authoritative = getBoolean(serverTable, "authoritative", true);
        Path jsonLogPath = Paths.get(getString(serverTable, "log_path", "logs/events.jsonl"));
        Path tsvLogPath = Paths.get(getString(serverTable, "tsv_log_path", "logs/events.tsv"));
        Path cleanJsonLogPath = Paths.get(getString(
                serverTable,
                "clean_log_path",
                "logs/events-clean.jsonl"));
        Path cleanTsvLogPath = Paths.get(getString(
                serverTable,
                "clean_tsv_log_path",
                "logs/events-clean.tsv"));
        String maxmindAsnDbPathRaw = getString(serverTable, "maxmind_asn_db_path", "GeoLite2-ASN.mmdb");
        Path maxmindAsnDbPath = maxmindAsnDbPathRaw.trim().isEmpty()
                ? null
                : Paths.get(maxmindAsnDbPathRaw);
        Path smtpMessageDir = Paths.get(getString(serverTable, "smtp_message_dir", "logs/smtp-messages"));

        String defaultResponseRaw = getString(serverTable, "default_response", "NXDOMAIN")
                .toUpperCase(Locale.ROOT);
        DefaultResponseMode defaultResponseMode;
        try {
            defaultResponseMode = DefaultResponseMode.valueOf(defaultResponseRaw);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("server.default_response must be NXDOMAIN or NODATA");
        }

        if (listenPort < 1 || listenPort > 65535) {
            throw new IllegalArgumentException("server.listen_port must be 1-65535");
        }

        SinkholeConfig.TcpServiceConfig httpConfig = parseTcpServiceConfig(
                "http",
                httpTable,
                listenAddress,
                80,
                5000,
                16384,
                true,
                false);
        SinkholeConfig.TcpServiceConfig smtpConfig = parseTcpServiceConfig(
                "smtp",
                smtpTable,
                listenAddress,
                25,
                8000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig ftpConfig = parseTcpServiceConfig(
                "ftp",
                ftpTable,
                listenAddress,
                21,
                8000,
                16384,
                false,
                false);
        SinkholeConfig.TcpServiceConfig imapConfig = parseTcpServiceConfig(
                "imap",
                imapTable,
                listenAddress,
                143,
                8000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig imapsConfig = parseTcpServiceConfig(
                "imaps",
                imapsTable,
                listenAddress,
                993,
                8000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig pop3Config = parseTcpServiceConfig(
                "pop3",
                pop3Table,
                listenAddress,
                110,
                8000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig pop3sConfig = parseTcpServiceConfig(
                "pop3s",
                pop3sTable,
                listenAddress,
                995,
                8000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig sshConfig = parseTcpServiceConfig(
                "ssh",
                sshTable,
                listenAddress,
                22,
                8000,
                16384,
                false,
                false);
        SinkholeConfig.TcpServiceConfig ldapConfig = parseTcpServiceConfig(
                "ldap",
                ldapTable,
                listenAddress,
                389,
                8000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig ldapsConfig = parseTcpServiceConfig(
                "ldaps",
                ldapsTable,
                listenAddress,
                636,
                8000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig kerberosConfig = parseTcpServiceConfig(
                "kerberos",
                kerberosTable,
                listenAddress,
                88,
                5000,
                16384,
                false,
                false);
        SinkholeConfig.TcpServiceConfig smbConfig = parseTcpServiceConfig(
                "smb",
                smbTable,
                listenAddress,
                445,
                5000,
                65536,
                false,
                false);
        SinkholeConfig.TcpServiceConfig rdpConfig = parseTcpServiceConfig(
                "rdp",
                rdpTable,
                listenAddress,
                3389,
                5000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig rpcConfig = parseTcpServiceConfig(
                "rpc",
                rpcTable,
                listenAddress,
                135,
                5000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig netbiosConfig = parseTcpServiceConfig(
                "netbios",
                netbiosTable,
                listenAddress,
                139,
                5000,
                32768,
                false,
                false);
        SinkholeConfig.TcpServiceConfig winrmHttpConfig = parseTcpServiceConfig(
                "winrm_http",
                winrmHttpTable,
                listenAddress,
                5985,
                8000,
                65536,
                false,
                false);
        SinkholeConfig.TcpServiceConfig winrmHttpsConfig = parseTcpServiceConfig(
                "winrm_https",
                winrmHttpsTable,
                listenAddress,
                5986,
                8000,
                65536,
                true,
                true);

        List<Zone> zones = new ArrayList<>();
        for (int i = 0; i < zoneTables.size(); i++) {
            Map<String, Object> zoneTable = zoneTables.get(i);
            String domain = getRequiredString(zoneTable, "domain", "zones[" + i + "]");
            int ttl = getInt(zoneTable, "ttl", 60);
            if (ttl < 0) {
                throw new IllegalArgumentException("zones[" + i + "].ttl must be >= 0");
            }

            List<String> answers = getStringList(zoneTable, "answer_ipv4", true, "zones[" + i + "]");
            List<Inet4Address> answerIpv4 = new ArrayList<>();
            for (String answer : answers) {
                answerIpv4.add(parseIpv4(answer, "zones[" + i + "].answer_ipv4"));
            }

            List<String> tags = getStringList(zoneTable, "tags", false, "zones[" + i + "]");
            zones.add(new Zone(domain, answerIpv4, ttl, tags));
        }

        return new SinkholeConfig(
                listenAddress,
                listenPort,
                authoritative,
                defaultResponseMode,
                jsonLogPath,
                tsvLogPath,
                cleanJsonLogPath,
                cleanTsvLogPath,
                maxmindAsnDbPath,
                smtpMessageDir,
                httpConfig,
                smtpConfig,
                ftpConfig,
                imapConfig,
                imapsConfig,
                pop3Config,
                pop3sConfig,
                sshConfig,
                ldapConfig,
                ldapsConfig,
                kerberosConfig,
                smbConfig,
                rdpConfig,
                rpcConfig,
                netbiosConfig,
                winrmHttpConfig,
                winrmHttpsConfig,
                zones);
    }

    private static String stripComments(String line) {
        boolean inString = false;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"' && !isEscaped(line, i)) {
                inString = !inString;
                out.append(c);
                continue;
            }
            if (c == '#' && !inString) {
                break;
            }
            out.append(c);
        }
        return out.toString();
    }

    private static boolean isEscaped(String value, int index) {
        int slashCount = 0;
        for (int i = index - 1; i >= 0 && value.charAt(i) == '\\'; i--) {
            slashCount++;
        }
        return slashCount % 2 == 1;
    }

    private static Object parseValue(String valueText, int lineNo) {
        if (valueText.startsWith("\"")) {
            if (!valueText.endsWith("\"") || valueText.length() < 2) {
                throw new IllegalArgumentException("Unterminated string at line " + lineNo);
            }
            return unescape(valueText.substring(1, valueText.length() - 1));
        }

        if (valueText.startsWith("[") && valueText.endsWith("]")) {
            String inner = valueText.substring(1, valueText.length() - 1).trim();
            if (inner.isEmpty()) {
                return List.of();
            }
            List<String> chunks = splitArrayValues(inner, lineNo);
            List<Object> values = new ArrayList<>();
            for (String chunk : chunks) {
                values.add(parseValue(chunk.trim(), lineNo));
            }
            return values;
        }

        if ("true".equals(valueText)) {
            return Boolean.TRUE;
        }
        if ("false".equals(valueText)) {
            return Boolean.FALSE;
        }

        if (valueText.matches("[-+]?\\d+")) {
            try {
                return Integer.parseInt(valueText);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid integer at line " + lineNo);
            }
        }

        return valueText;
    }

    private static List<String> splitArrayValues(String inner, int lineNo) {
        List<String> values = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inString = false;

        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (c == '"' && !isEscaped(inner, i)) {
                inString = !inString;
                current.append(c);
                continue;
            }

            if (c == ',' && !inString) {
                String token = current.toString().trim();
                if (token.isEmpty()) {
                    throw new IllegalArgumentException("Empty array value at line " + lineNo);
                }
                values.add(token);
                current.setLength(0);
                continue;
            }

            current.append(c);
        }

        if (inString) {
            throw new IllegalArgumentException("Unterminated string in array at line " + lineNo);
        }

        String token = current.toString().trim();
        if (token.isEmpty()) {
            throw new IllegalArgumentException("Empty array value at line " + lineNo);
        }
        values.add(token);
        return values;
    }

    private static String unescape(String raw) {
        StringBuilder out = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (i + 1 >= raw.length()) {
                out.append('\\');
                break;
            }
            char next = raw.charAt(++i);
            switch (next) {
            case 'n':
                out.append('\n');
                break;
            case 't':
                out.append('\t');
                break;
            case 'r':
                out.append('\r');
                break;
            case '"':
                out.append('"');
                break;
            case '\\':
                out.append('\\');
                break;
            default:
                out.append(next);
                break;
            }
        }
        return out.toString();
    }

    private static String getString(Map<String, Object> table, String key, String defaultValue) {
        Object value = table.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof String)) {
            throw new IllegalArgumentException("Expected string for key: " + key);
        }
        return (String) value;
    }

    private static String getRequiredString(Map<String, Object> table, String key, String tableName) {
        Object value = table.get(key);
        if (value == null) {
            throw new IllegalArgumentException(tableName + "." + key + " is required");
        }
        if (!(value instanceof String)) {
            throw new IllegalArgumentException(tableName + "." + key + " must be a string");
        }
        String asString = ((String) value).trim();
        if (asString.isEmpty()) {
            throw new IllegalArgumentException(tableName + "." + key + " must not be empty");
        }
        return asString;
    }

    private static int getInt(Map<String, Object> table, String key, int defaultValue) {
        Object value = table.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof Integer)) {
            throw new IllegalArgumentException("Expected integer for key: " + key);
        }
        return (Integer) value;
    }

    private static boolean getBoolean(Map<String, Object> table, String key, boolean defaultValue) {
        Object value = table.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof Boolean)) {
            throw new IllegalArgumentException("Expected boolean for key: " + key);
        }
        return (Boolean) value;
    }

    private static List<String> getStringList(
            Map<String, Object> table,
            String key,
            boolean required,
            String tableName) {
        Object value = table.get(key);
        if (value == null) {
            if (required) {
                throw new IllegalArgumentException(tableName + "." + key + " is required");
            }
            return List.of();
        }
        if (!(value instanceof List<?>)) {
            throw new IllegalArgumentException(tableName + "." + key + " must be an array");
        }
        List<?> list = (List<?>) value;
        List<String> output = new ArrayList<>();
        for (Object entry : list) {
            if (!(entry instanceof String)) {
                throw new IllegalArgumentException(tableName + "." + key + " must only contain strings");
            }
            output.add((String) entry);
        }
        if (required && output.isEmpty()) {
            throw new IllegalArgumentException(tableName + "." + key + " must contain at least one value");
        }
        return output;
    }

    private static SinkholeConfig.TcpServiceConfig parseTcpServiceConfig(
            String tableName,
            Map<String, Object> table,
            String defaultAddress,
            int defaultPort,
            int defaultReadTimeoutMs,
            int defaultCaptureMaxBytes,
            boolean supportsTls,
            boolean defaultTlsEnabled) {
        boolean enabled = getBoolean(table, "enabled", false);
        String listenAddress = getString(table, "listen_address", defaultAddress);
        int listenPort = getInt(table, "listen_port", defaultPort);
        int readTimeoutMs = getInt(table, "read_timeout_ms", defaultReadTimeoutMs);
        int captureMaxBytes = getInt(table, "capture_max_bytes", defaultCaptureMaxBytes);
        boolean tlsEnabled = getBoolean(table, "tls_enabled", defaultTlsEnabled);
        String tlsKeystorePath = getString(table, "tls_keystore_path", "");
        String tlsKeystorePassword = getString(table, "tls_keystore_password", "");
        String tlsKeyPassword = getString(table, "tls_key_password", "");
        String tlsKeystoreType = getString(table, "tls_keystore_type", "PKCS12");

        if (listenPort < 1 || listenPort > 65535) {
            throw new IllegalArgumentException(tableName + ".listen_port must be 1-65535");
        }
        if (readTimeoutMs < 100) {
            throw new IllegalArgumentException(tableName + ".read_timeout_ms must be >= 100");
        }
        if (captureMaxBytes < 256) {
            throw new IllegalArgumentException(tableName + ".capture_max_bytes must be >= 256");
        }
        if (enabled && tlsEnabled && !supportsTls) {
            throw new IllegalArgumentException(tableName + ".tls_enabled is not supported");
        }
        if (enabled && tlsEnabled) {
            if (tlsKeystorePath.trim().isEmpty()) {
                throw new IllegalArgumentException(tableName + ".tls_keystore_path is required when tls_enabled=true");
            }
            if (tlsKeystorePassword.isEmpty()) {
                throw new IllegalArgumentException(
                        tableName + ".tls_keystore_password is required when tls_enabled=true");
            }
            if (tlsKeystoreType.trim().isEmpty()) {
                throw new IllegalArgumentException(tableName + ".tls_keystore_type must not be empty");
            }
        }

        return new SinkholeConfig.TcpServiceConfig(
                enabled,
                listenAddress,
                listenPort,
                readTimeoutMs,
                captureMaxBytes,
                tlsEnabled,
                tlsKeystorePath,
                tlsKeystorePassword,
                tlsKeyPassword,
                tlsKeystoreType);
    }

    private static Inet4Address parseIpv4(String raw, String fieldName) {
        try {
            InetAddress parsed = InetAddress.getByName(raw);
            if (!(parsed instanceof Inet4Address)) {
                throw new IllegalArgumentException(fieldName + " only supports IPv4 addresses");
            }
            return (Inet4Address) parsed;
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv4 address in " + fieldName + ": " + raw);
        }
    }
}
