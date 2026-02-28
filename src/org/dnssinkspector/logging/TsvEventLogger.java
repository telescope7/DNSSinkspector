package org.dnssinkspector.logging;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class TsvEventLogger implements EventLogger {
    private static final List<String> ALL_COLUMNS = List.of(
            "timestamp_utc",
            "event_type",
            "protocol",
            "transport",
            "client_ip",
            "client_asn_number",
            "client_asn_name",
            "client_port",
            "server_ip",
            "server_asn_number",
            "server_asn_name",
            "server_port",
            "session_id",
            "transaction_id",
            "recursion_desired",
            "query_name",
            "query_type",
            "query_type_name",
            "query_class",
            "query_class_name",
            "matched_zone",
            "zone_tags",
            "decision",
            "response_rcode",
            "response_rcode_name",
            "answer_count",
            "answer_ipv4",
            "authoritative",
            "request_size_bytes",
            "response_size_bytes",
            "latency_ms",
            "smtp_mail_from",
            "smtp_rcpt_to",
            "smtp_message_path",
            "smtp_message_size_bytes",
            "smtp_message_error",
            "ldap_message_id",
            "ldap_operations",
            "ldap_bind_dn",
            "ldap_bind_auth_type",
            "ldap_bind_sasl_mechanism",
            "ldap_search_base",
            "ldap_search_filter",
            "ldap_starttls_requested",
            "smb_dialect",
            "smb_command",
            "smb_command_name",
            "smb_message_id",
            "smb_tree_id",
            "smb_session_id",
            "ntlmssp_message_type",
            "ntlmssp_username",
            "ntlmssp_domain",
            "ntlmssp_workstation",
            "ntlmssp_lm_response_len",
            "ntlmssp_nt_response_len",
            "username",
            "password",
            "data_text",
            "data_base64",
            "truncated",
            "error",
            "parse_error");

    private final BufferedWriter writer;
    private final List<String> columns;

    public TsvEventLogger(Path tsvPath) throws IOException {
        this(tsvPath, Set.of());
    }

    public TsvEventLogger(Path tsvPath, Set<String> excludedColumns) throws IOException {
        Path parent = tsvPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        this.columns = selectColumns(excludedColumns);

        boolean writeHeader = !Files.exists(tsvPath) || Files.size(tsvPath) == 0;
        this.writer = Files.newBufferedWriter(
                tsvPath,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);

        if (writeHeader) {
            writer.write(String.join("\t", columns));
            writer.newLine();
            writer.flush();
        }
    }

    @Override
    public synchronized void logEvent(Map<String, Object> event) {
        try {
            List<String> values = new ArrayList<>(columns.size());
            for (String column : columns) {
                values.add(escapeTsv(toFlatString(event.get(column))));
            }
            writer.write(String.join("\t", values));
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            System.err.println("Failed to write TSV event: " + e.getMessage());
        }
    }

    @Override
    public synchronized void close() {
        try {
            writer.close();
        } catch (IOException e) {
            System.err.println("Failed to close TSV logger: " + e.getMessage());
        }
    }

    private static String toFlatString(Object value) {
        if (value == null) {
            return "";
        }
        if (value instanceof List<?>) {
            List<?> list = (List<?>) value;
            List<String> values = new ArrayList<>(list.size());
            for (Object entry : list) {
                values.add(entry == null ? "" : String.valueOf(entry));
            }
            return String.join(",", values);
        }
        return String.valueOf(value);
    }

    private static String escapeTsv(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\t", "\\t")
                .replace("\r", "\\r")
                .replace("\n", "\\n");
    }

    private static List<String> selectColumns(Set<String> excludedColumns) {
        if (excludedColumns.isEmpty()) {
            return ALL_COLUMNS;
        }
        List<String> selected = new ArrayList<>(ALL_COLUMNS.size());
        for (String column : ALL_COLUMNS) {
            if (!excludedColumns.contains(column)) {
                selected.add(column);
            }
        }
        return List.copyOf(selected);
    }
}
