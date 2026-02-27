package org.dnssinkspector.dns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.dnssinkspector.config.SinkholeConfig;
import org.dnssinkspector.config.SinkholeConfig.DefaultResponseMode;
import org.dnssinkspector.config.SinkholeConfig.Zone;
import org.dnssinkspector.logging.EventLogger;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;
import org.xbill.DNS.WireParseException;

public final class DnsServer {
    private static final int MAX_PACKET_BYTES = 2048;

    private final SinkholeConfig config;
    private final EventLogger eventLogger;
    private volatile boolean running;
    private DatagramSocket socket;

    public DnsServer(SinkholeConfig config, EventLogger eventLogger) {
        this.config = config;
        this.eventLogger = eventLogger;
    }

    public void start() throws IOException {
        socket = new DatagramSocket(new InetSocketAddress(config.getListenAddress(), config.getListenPort()));
        running = true;

        while (running) {
            DatagramPacket packet = new DatagramPacket(new byte[MAX_PACKET_BYTES], MAX_PACKET_BYTES);
            try {
                socket.receive(packet);
            } catch (SocketException e) {
                if (running) {
                    throw e;
                }
                break;
            }
            handlePacket(packet);
        }
    }

    public void stop() {
        running = false;
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
    }

    private void handlePacket(DatagramPacket packet) {
        long startedAtNanos = System.nanoTime();
        byte[] requestPacket = Arrays.copyOfRange(
                packet.getData(),
                packet.getOffset(),
                packet.getOffset() + packet.getLength());

        int txid = readTransactionId(requestPacket);
        boolean recursionDesired = readRecursionDesired(requestPacket);

        DnsQueryInfo query = null;
        DnsResponsePlan plan = null;
        Zone matchedZone = null;
        byte[] response = null;
        String parseError = null;

        try {
            Message queryMessage = new Message(requestPacket);
            query = DnsQueryInfo.fromMessage(queryMessage);
            txid = query.transactionId();
            recursionDesired = query.recursionDesired();

            Optional<Zone> zoneMatch = config.findZone(query.queryName());
            if (zoneMatch.isPresent()) {
                matchedZone = zoneMatch.get();
                if (query.queryClass() != DClass.IN) {
                    plan = DnsResponsePlan.noData("matched_zone_unsupported_class");
                } else if (query.queryType() == Type.A || query.queryType() == Type.ANY) {
                    plan = DnsResponsePlan.matchedZone(matchedZone.getAnswerIpv4(), matchedZone.getTtlSeconds());
                } else {
                    plan = DnsResponsePlan.noData("matched_zone_unsupported_qtype");
                }
            } else {
                if (config.getDefaultResponseMode() == DefaultResponseMode.NXDOMAIN) {
                    plan = DnsResponsePlan.nxdomain("default_nxdomain");
                } else {
                    plan = DnsResponsePlan.noData("default_nodata");
                }
            }

            response = buildResponse(query, plan);
            sendResponse(response, packet);
        } catch (Exception e) {
            parseError = e.getMessage();
            plan = DnsResponsePlan.formerr("parse_error");
            try {
                response = buildMinimalErrorResponse(txid, recursionDesired, DnsResponsePlan.RCODE_FORMERR);
                sendResponse(response, packet);
            } catch (IOException sendError) {
                parseError = parseError + "; failed to send FORMERR response: " + sendError.getMessage();
            }
        } finally {
            logEvent(packet, requestPacket, response, query, matchedZone, plan, parseError, startedAtNanos);
        }
    }

    private void sendResponse(byte[] response, DatagramPacket requestPacket) throws IOException {
        DatagramPacket reply = new DatagramPacket(
                response,
                response.length,
                requestPacket.getAddress(),
                requestPacket.getPort());
        socket.send(reply);
    }

    private void logEvent(
            DatagramPacket requestPacket,
            byte[] requestPayload,
            byte[] responsePayload,
            DnsQueryInfo query,
            Zone matchedZone,
            DnsResponsePlan plan,
            String parseError,
            long startedAtNanos) {
        long elapsedMs = (System.nanoTime() - startedAtNanos) / 1_000_000L;
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("timestamp_utc", Instant.now().toString());
        event.put("event_type", "dns_query");
        event.put("protocol", "DNS");
        event.put("transport", "udp");
        event.put("client_ip", requestPacket.getAddress().getHostAddress());
        event.put("client_port", requestPacket.getPort());
        event.put("server_ip", socket.getLocalAddress().getHostAddress());
        event.put("server_port", socket.getLocalPort());

        if (query != null) {
            event.put("transaction_id", query.transactionId());
            event.put("recursion_desired", query.recursionDesired());
            event.put("query_name", query.queryName());
            event.put("query_type", query.queryType());
            event.put("query_type_name", Type.string(query.queryType()));
            event.put("query_class", query.queryClass());
            event.put("query_class_name", DClass.string(query.queryClass()));
        } else {
            event.put("transaction_id", readTransactionId(requestPayload));
            event.put("recursion_desired", readRecursionDesired(requestPayload));
            event.put("query_name", null);
            event.put("query_type", null);
            event.put("query_type_name", null);
            event.put("query_class", null);
            event.put("query_class_name", null);
        }

        if (matchedZone != null) {
            event.put("matched_zone", matchedZone.getDomain());
            event.put("zone_tags", matchedZone.getTags());
        } else {
            event.put("matched_zone", null);
            event.put("zone_tags", List.of());
        }

        if (plan != null) {
            event.put("decision", plan.getDecision());
            event.put("response_rcode", plan.getRcode());
            event.put("response_rcode_name", Rcode.string(plan.getRcode()));
            event.put("answer_count", plan.getAnswerIpv4().size());
            event.put("answer_ipv4", toIpv4Strings(plan.getAnswerIpv4()));
        } else {
            event.put("decision", "internal_error");
            event.put("response_rcode", null);
            event.put("response_rcode_name", null);
            event.put("answer_count", 0);
            event.put("answer_ipv4", List.of());
        }

        event.put("authoritative", config.isAuthoritative());
        event.put("request_size_bytes", requestPayload.length);
        event.put("response_size_bytes", responsePayload == null ? 0 : responsePayload.length);
        event.put("latency_ms", elapsedMs);
        event.put("parse_error", parseError);

        eventLogger.logEvent(event);
    }

    private byte[] buildResponse(DnsQueryInfo query, DnsResponsePlan plan) throws IOException {
        Message response = new Message();
        Header header = response.getHeader();
        header.setID(query.transactionId());
        header.setFlag(Flags.QR);
        if (config.isAuthoritative()) {
            header.setFlag(Flags.AA);
        }
        if (query.recursionDesired()) {
            header.setFlag(Flags.RD);
        }
        header.setOpcode(query.opcode());
        header.setRcode(plan.getRcode());

        response.addRecord(query.questionRecord(), Section.QUESTION);
        if (plan.getRcode() == DnsResponsePlan.RCODE_NOERROR) {
            for (Inet4Address answerIpv4 : plan.getAnswerIpv4()) {
                response.addRecord(
                        new ARecord(query.questionName(), DClass.IN, plan.getTtlSeconds(), answerIpv4),
                        Section.ANSWER);
            }
        }

        return response.toWire(MAX_PACKET_BYTES);
    }

    private byte[] buildMinimalErrorResponse(int transactionId, boolean recursionDesired, int rcode) {
        Message response = new Message();
        Header header = response.getHeader();
        header.setID(transactionId);
        header.setFlag(Flags.QR);
        if (recursionDesired) {
            header.setFlag(Flags.RD);
        }
        header.setRcode(rcode);
        return response.toWire();
    }

    private static int readTransactionId(byte[] packet) {
        if (packet.length < 2) {
            return 0;
        }
        return ((packet[0] & 0xFF) << 8) | (packet[1] & 0xFF);
    }

    private static boolean readRecursionDesired(byte[] packet) {
        if (packet.length < 4) {
            return false;
        }
        int flags = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
        return (flags & 0x0100) != 0;
    }

    private static List<String> toIpv4Strings(List<Inet4Address> addresses) {
        List<String> values = new ArrayList<>(addresses.size());
        for (Inet4Address address : addresses) {
            values.add(address.getHostAddress());
        }
        return values;
    }

    private record DnsQueryInfo(
            int transactionId,
            int opcode,
            boolean recursionDesired,
            String queryName,
            Name questionName,
            int queryType,
            int queryClass,
            Record questionRecord) {
        private static DnsQueryInfo fromMessage(Message message) throws WireParseException {
            Record question = message.getQuestion();
            if (question == null) {
                throw new WireParseException("DNS question section is empty");
            }
            Header header = message.getHeader();
            Name qname = question.getName();
            return new DnsQueryInfo(
                    header.getID(),
                    header.getOpcode(),
                    header.getFlag(Flags.RD),
                    qname.toString(true),
                    qname,
                    question.getType(),
                    question.getDClass(),
                    question);
        }
    }
}
