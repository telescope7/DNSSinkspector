package org.dnssinkspector.dns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class DnsPacketCodec {
    private static final int DNS_HEADER_SIZE = 12;
    private static final int CLASS_IN = 1;
    private static final int TYPE_A = 1;

    private DnsPacketCodec() {
    }

    public static DnsQuery parseQuery(byte[] packet, int length) throws IOException {
        if (length < DNS_HEADER_SIZE) {
            throw new IOException("DNS packet too short");
        }

        int transactionId = readU16(packet, 0);
        int flags = readU16(packet, 2);
        int questionCount = readU16(packet, 4);
        if (questionCount < 1) {
            throw new IOException("DNS question section is empty");
        }

        NameReadResult nameResult = readName(packet, length, DNS_HEADER_SIZE);
        int offset = DNS_HEADER_SIZE + nameResult.bytesConsumed;
        if (offset + 4 > length) {
            throw new IOException("Incomplete DNS question");
        }

        int qtype = readU16(packet, offset);
        int qclass = readU16(packet, offset + 2);
        return new DnsQuery(transactionId, flags, nameResult.name, qtype, qclass);
    }

    public static byte[] buildResponse(DnsQuery query, DnsResponsePlan plan, boolean authoritative) throws IOException {
        List<Inet4Address> answers = plan.getRcode() == DnsResponsePlan.RCODE_NOERROR
                ? plan.getAnswerIpv4()
                : List.of();

        ByteArrayOutputStream out = new ByteArrayOutputStream(512);
        writeU16(out, query.getTransactionId());
        writeU16(out, buildResponseFlags(query, plan.getRcode(), authoritative));
        writeU16(out, 1); // QDCOUNT
        writeU16(out, answers.size()); // ANCOUNT
        writeU16(out, 0); // NSCOUNT
        writeU16(out, 0); // ARCOUNT

        writeDomainName(out, query.getQname());
        writeU16(out, query.getQtype());
        writeU16(out, query.getQclass());

        for (Inet4Address answer : answers) {
            out.write(0xC0);
            out.write(0x0C);
            writeU16(out, TYPE_A);
            writeU16(out, CLASS_IN);
            writeU32(out, plan.getTtlSeconds());
            writeU16(out, 4);
            out.write(answer.getAddress());
        }

        return out.toByteArray();
    }

    public static byte[] buildMinimalErrorResponse(int transactionId, boolean recursionDesired, int rcode)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        writeU16(out, transactionId);
        int flags = 0x8000;
        if (recursionDesired) {
            flags |= 0x0100;
        }
        flags |= (rcode & 0xF);
        writeU16(out, flags);
        writeU16(out, 0);
        writeU16(out, 0);
        writeU16(out, 0);
        writeU16(out, 0);
        return out.toByteArray();
    }

    public static int readTransactionId(byte[] packet, int length) {
        if (length < 2) {
            return 0;
        }
        return readU16(packet, 0);
    }

    public static boolean readRecursionDesired(byte[] packet, int length) {
        if (length < 4) {
            return false;
        }
        int flags = readU16(packet, 2);
        return (flags & 0x0100) != 0;
    }

    public static String typeName(int qtype) {
        switch (qtype) {
        case 1:
            return "A";
        case 2:
            return "NS";
        case 5:
            return "CNAME";
        case 6:
            return "SOA";
        case 12:
            return "PTR";
        case 15:
            return "MX";
        case 16:
            return "TXT";
        case 28:
            return "AAAA";
        case 33:
            return "SRV";
        case 255:
            return "ANY";
        default:
            return "TYPE" + qtype;
        }
    }

    public static String className(int qclass) {
        if (qclass == 1) {
            return "IN";
        }
        return "CLASS" + qclass;
    }

    public static String rcodeName(int rcode) {
        switch (rcode) {
        case 0:
            return "NOERROR";
        case 1:
            return "FORMERR";
        case 2:
            return "SERVFAIL";
        case 3:
            return "NXDOMAIN";
        case 4:
            return "NOTIMP";
        case 5:
            return "REFUSED";
        default:
            return "RCODE" + rcode;
        }
    }

    private static int buildResponseFlags(DnsQuery query, int rcode, boolean authoritative) {
        int flags = 0x8000; // QR=1
        flags |= (query.getFlags() & 0x7800); // preserve OPCODE
        if (authoritative) {
            flags |= 0x0400; // AA
        }
        if (query.isRecursionDesired()) {
            flags |= 0x0100; // RD
        }
        flags |= (rcode & 0xF);
        return flags;
    }

    private static NameReadResult readName(byte[] packet, int length, int offset) throws IOException {
        StringBuilder builder = new StringBuilder();
        int current = offset;
        int consumed = 0;
        boolean jumped = false;
        Set<Integer> visitedPointers = new HashSet<>();

        while (true) {
            if (current >= length) {
                throw new IOException("DNS name exceeds packet length");
            }
            int len = packet[current] & 0xFF;
            if ((len & 0xC0) == 0xC0) {
                if (current + 1 >= length) {
                    throw new IOException("Incomplete DNS compression pointer");
                }
                int pointer = ((len & 0x3F) << 8) | (packet[current + 1] & 0xFF);
                if (!visitedPointers.add(pointer)) {
                    throw new IOException("DNS compression pointer loop");
                }
                if (!jumped) {
                    consumed += 2;
                }
                current = pointer;
                jumped = true;
                continue;
            }

            if (len == 0) {
                if (!jumped) {
                    consumed += 1;
                }
                break;
            }

            if (len > 63) {
                throw new IOException("Invalid DNS label length: " + len);
            }
            int labelStart = current + 1;
            int labelEnd = labelStart + len;
            if (labelEnd > length) {
                throw new IOException("DNS label exceeds packet length");
            }

            if (builder.length() > 0) {
                builder.append('.');
            }
            builder.append(new String(packet, labelStart, len, StandardCharsets.US_ASCII));

            if (!jumped) {
                consumed += 1 + len;
            }
            current = labelEnd;
        }

        return new NameReadResult(builder.toString(), consumed);
    }

    private static void writeDomainName(ByteArrayOutputStream out, String domainName) throws IOException {
        if (domainName == null || domainName.isEmpty()) {
            out.write(0);
            return;
        }
        String canonical = domainName.endsWith(".")
                ? domainName.substring(0, domainName.length() - 1)
                : domainName;
        if (canonical.isEmpty()) {
            out.write(0);
            return;
        }

        String[] labels = canonical.split("\\.");
        for (String label : labels) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            if (bytes.length == 0 || bytes.length > 63) {
                throw new IOException("Invalid DNS label in domain: " + domainName);
            }
            out.write(bytes.length);
            out.write(bytes);
        }
        out.write(0);
    }

    private static int readU16(byte[] packet, int offset) {
        return ((packet[offset] & 0xFF) << 8) | (packet[offset + 1] & 0xFF);
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeU32(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static final class NameReadResult {
        private final String name;
        private final int bytesConsumed;

        private NameReadResult(String name, int bytesConsumed) {
            this.name = name;
            this.bytesConsumed = bytesConsumed;
        }
    }
}
