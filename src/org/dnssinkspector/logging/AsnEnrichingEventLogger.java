package org.dnssinkspector.logging;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;

public final class AsnEnrichingEventLogger implements EventLogger {
    private static final AsnLookupResult EMPTY_RESULT = new AsnLookupResult(null, null);

    private final EventLogger delegate;
    private final DatabaseReader asnDatabase;
    private final ConcurrentMap<String, AsnLookupResult> lookupCache = new ConcurrentHashMap<>();

    public AsnEnrichingEventLogger(EventLogger delegate, Path asnDatabasePath) throws IOException {
        this.delegate = delegate;
        this.asnDatabase = new DatabaseReader.Builder(asnDatabasePath.toFile()).build();
    }

    @Override
    public void logEvent(Map<String, Object> event) {
        Map<String, Object> enriched = new LinkedHashMap<>(event);
        enrichIp(enriched, "client_ip", "client_asn_number", "client_asn_name");
        enrichIp(enriched, "server_ip", "server_asn_number", "server_asn_name");
        delegate.logEvent(enriched);
    }

    @Override
    public void close() throws IOException {
        IOException firstError = null;
        try {
            delegate.close();
        } catch (IOException e) {
            firstError = e;
        }

        try {
            asnDatabase.close();
        } catch (IOException e) {
            if (firstError == null) {
                firstError = e;
            } else {
                firstError.addSuppressed(e);
            }
        }

        if (firstError != null) {
            throw firstError;
        }
    }

    private void enrichIp(Map<String, Object> event, String ipField, String asnNumberField, String asnNameField) {
        Object rawIp = event.get(ipField);
        if (!(rawIp instanceof String)) {
            event.put(asnNumberField, null);
            event.put(asnNameField, null);
            return;
        }

        String ip = ((String) rawIp).trim();
        if (ip.isEmpty()) {
            event.put(asnNumberField, null);
            event.put(asnNameField, null);
            return;
        }

        AsnLookupResult result = lookupCache.computeIfAbsent(ip, this::lookup);
        event.put(asnNumberField, result.number());
        event.put(asnNameField, result.name());
    }

    private AsnLookupResult lookup(String ip) {
        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            AsnResponse response = asnDatabase.asn(inetAddress);
            return new AsnLookupResult(
                    response.getAutonomousSystemNumber(),
                    response.getAutonomousSystemOrganization());
        } catch (IOException | GeoIp2Exception | RuntimeException e) {
            return EMPTY_RESULT;
        }
    }

    private record AsnLookupResult(Long number, String name) {
    }
}
