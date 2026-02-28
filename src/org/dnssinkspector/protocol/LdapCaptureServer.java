package org.dnssinkspector.protocol;

import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;

public final class LdapCaptureServer extends AbstractTcpCaptureServer {
    private static final String LDAP_STARTTLS_OID = "1.3.6.1.4.1.1466.20037";

    public LdapCaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        super("LDAP", config, eventLogger);
    }

    @Override
    protected TcpSessionCapture captureSession(Socket socket) throws IOException {
        TcpCaptureUtil.ReadResult readResult = TcpCaptureUtil.readUpTo(
                socket.getInputStream(),
                getConfig().getCaptureMaxBytes());
        byte[] payload = readResult.payload();

        LdapParseResult parsed = parsePayload(payload);
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("ldap_message_id", parsed.messageId);
        extra.put("ldap_operations", parsed.operations);
        extra.put("ldap_bind_dn", parsed.bindDn);
        extra.put("ldap_bind_auth_type", parsed.bindAuthType);
        extra.put("ldap_bind_sasl_mechanism", parsed.bindSaslMechanism);
        extra.put("ldap_search_base", parsed.searchBase);
        extra.put("ldap_search_filter", parsed.searchFilter);
        extra.put("ldap_starttls_requested", parsed.startTlsRequested);

        String decision;
        if (payload.length == 0) {
            decision = "captured_no_data_and_closed";
        } else if (readResult.truncated()) {
            decision = "captured_truncated_and_closed";
        } else if (parsed.simpleBindPassword != null || parsed.bindSaslMechanism != null) {
            decision = "captured_auth_material_and_closed";
        } else {
            decision = "captured_and_closed";
        }

        return new TcpSessionCapture(
                parsed.simpleBindDn,
                parsed.simpleBindPassword,
                new String(payload, StandardCharsets.UTF_8),
                Base64.getEncoder().encodeToString(payload),
                payload.length,
                readResult.truncated(),
                decision,
                null,
                extra);
    }

    private static LdapParseResult parsePayload(byte[] payload) {
        LdapParseResult result = new LdapParseResult();
        BerReader reader = new BerReader(payload, 0, payload.length);

        while (reader.hasRemaining()) {
            BerElement message;
            try {
                message = reader.readElement();
            } catch (RuntimeException e) {
                break;
            }
            if (message.tag != 0x30) {
                continue;
            }

            BerReader messageReader = message.reader();
            Integer messageId = null;
            if (messageReader.hasRemaining()) {
                BerElement idElement = messageReader.readElementSafe();
                if (idElement != null && idElement.tag == 0x02) {
                    messageId = parseInteger(idElement.value);
                    if (result.messageId == null) {
                        result.messageId = messageId;
                    }
                }
            }
            if (!messageReader.hasRemaining()) {
                continue;
            }

            BerElement opElement = messageReader.readElementSafe();
            if (opElement == null) {
                continue;
            }

            String opName = ldapOpName(opElement.tag);
            result.operations.add(opName);

            if (opElement.tag == 0x60) {
                parseBindRequest(opElement, result);
            } else if (opElement.tag == 0x63) {
                parseSearchRequest(opElement, result);
            } else if (opElement.tag == 0x77) {
                parseExtendedRequest(opElement, result);
            }
        }
        return result;
    }

    private static void parseBindRequest(BerElement opElement, LdapParseResult result) {
        BerReader bind = opElement.reader();
        BerElement versionElement = bind.readElementSafe();
        if (versionElement == null || versionElement.tag != 0x02) {
            return;
        }
        BerElement nameElement = bind.readElementSafe();
        if (nameElement == null || nameElement.tag != 0x04) {
            return;
        }

        String bindDn = decodeUtf8(nameElement.value);
        result.bindDn = firstNonBlank(result.bindDn, bindDn);

        BerElement authElement = bind.readElementSafe();
        if (authElement == null) {
            return;
        }

        if (authElement.tag == 0x80) {
            String password = decodeUtf8(authElement.value);
            result.bindAuthType = "simple";
            result.simpleBindDn = firstNonBlank(result.simpleBindDn, bindDn);
            if (password != null && !password.isBlank()) {
                result.simpleBindPassword = password;
            }
            return;
        }

        if (authElement.tag == 0xA3) {
            result.bindAuthType = "sasl";
            BerReader sasl = authElement.reader();
            BerElement mechElement = sasl.readElementSafe();
            if (mechElement != null && mechElement.tag == 0x04) {
                result.bindSaslMechanism = firstNonBlank(result.bindSaslMechanism, decodeUtf8(mechElement.value));
            }
        }
    }

    private static void parseSearchRequest(BerElement opElement, LdapParseResult result) {
        BerReader search = opElement.reader();
        BerElement baseElement = search.readElementSafe();
        if (baseElement != null && baseElement.tag == 0x04) {
            result.searchBase = firstNonBlank(result.searchBase, decodeUtf8(baseElement.value));
        }

        // Skip scope, derefAliases, sizeLimit, timeLimit, typesOnly.
        for (int i = 0; i < 5 && search.hasRemaining(); i++) {
            search.readElementSafe();
        }

        if (!search.hasRemaining()) {
            return;
        }
        BerElement filterElement = search.readElementSafe();
        if (filterElement == null) {
            return;
        }
        String filter = parseFilter(filterElement, 0);
        result.searchFilter = firstNonBlank(result.searchFilter, filter);
    }

    private static void parseExtendedRequest(BerElement opElement, LdapParseResult result) {
        BerReader ext = opElement.reader();
        while (ext.hasRemaining()) {
            BerElement child = ext.readElementSafe();
            if (child == null) {
                break;
            }
            if (child.tag == 0x80) {
                String oid = decodeUtf8(child.value);
                if (LDAP_STARTTLS_OID.equals(oid)) {
                    result.startTlsRequested = true;
                }
            }
        }
    }

    private static String parseFilter(BerElement filter, int depth) {
        if (depth > 8 || filter == null) {
            return "(filter-too-deep)";
        }
        int tag = filter.tag & 0xFF;
        switch (tag) {
        case 0xA0:
            return "(" + "&" + parseFilterSet(filter, depth + 1) + ")";
        case 0xA1:
            return "(" + "|" + parseFilterSet(filter, depth + 1) + ")";
        case 0xA2:
            return "(!" + parseFirstFilterChild(filter, depth + 1) + ")";
        case 0xA3:
            return parseAttributeValueFilter(filter, "=");
        case 0xA5:
            return parseAttributeValueFilter(filter, ">=");
        case 0xA6:
            return parseAttributeValueFilter(filter, "<=");
        case 0xA8:
            return parseAttributeValueFilter(filter, "~=");
        case 0x87:
            return "(" + safeFilterText(decodeUtf8(filter.value)) + "=*)";
        default:
            return "(tag-0x" + Integer.toHexString(tag).toUpperCase(Locale.ROOT) + ")";
        }
    }

    private static String parseFilterSet(BerElement filter, int depth) {
        BerReader reader = filter.reader();
        StringBuilder combined = new StringBuilder();
        while (reader.hasRemaining()) {
            BerElement child = reader.readElementSafe();
            if (child == null) {
                break;
            }
            combined.append(parseFilter(child, depth));
        }
        return combined.toString();
    }

    private static String parseFirstFilterChild(BerElement filter, int depth) {
        BerReader reader = filter.reader();
        BerElement child = reader.readElementSafe();
        if (child == null) {
            return "(empty)";
        }
        return parseFilter(child, depth);
    }

    private static String parseAttributeValueFilter(BerElement filter, String operator) {
        BerReader reader = filter.reader();
        BerElement attribute = reader.readElementSafe();
        BerElement value = reader.readElementSafe();
        String attr = attribute != null ? decodeUtf8(attribute.value) : "";
        String val = value != null ? decodeUtf8(value.value) : "";
        return "(" + safeFilterText(attr) + operator + safeFilterText(val) + ")";
    }

    private static String safeFilterText(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("(", "\\28").replace(")", "\\29");
    }

    private static String firstNonBlank(String existing, String candidate) {
        if (existing != null && !existing.isBlank()) {
            return existing;
        }
        return candidate;
    }

    private static String decodeUtf8(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static int parseInteger(byte[] bytes) {
        int value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xFF);
        }
        return value;
    }

    private static String ldapOpName(int tag) {
        return switch (tag & 0xFF) {
        case 0x60 -> "BindRequest";
        case 0x61 -> "BindResponse";
        case 0x63 -> "SearchRequest";
        case 0x64 -> "SearchResultEntry";
        case 0x65 -> "SearchResultDone";
        case 0x66 -> "ModifyRequest";
        case 0x68 -> "AddRequest";
        case 0x6A -> "DelRequest";
        case 0x6C -> "ModifyDNRequest";
        case 0x6E -> "CompareRequest";
        case 0x70 -> "AbandonRequest";
        case 0x73 -> "SearchResultReference";
        case 0x77 -> "ExtendedRequest";
        case 0x78 -> "ExtendedResponse";
        default -> "Tag0x" + Integer.toHexString(tag & 0xFF).toUpperCase(Locale.ROOT);
        };
    }

    private static final class LdapParseResult {
        private Integer messageId;
        private final List<String> operations = new ArrayList<>();
        private String bindDn;
        private String bindAuthType;
        private String bindSaslMechanism;
        private String simpleBindDn;
        private String simpleBindPassword;
        private String searchBase;
        private String searchFilter;
        private boolean startTlsRequested;
    }

    private static final class BerElement {
        private final int tag;
        private final byte[] value;

        private BerElement(int tag, byte[] value) {
            this.tag = tag;
            this.value = value;
        }

        private BerReader reader() {
            return new BerReader(value, 0, value.length);
        }
    }

    private static final class BerReader {
        private final byte[] data;
        private final int limit;
        private int position;

        private BerReader(byte[] data, int offset, int length) {
            this.data = data;
            this.position = offset;
            this.limit = Math.min(data.length, offset + length);
        }

        private boolean hasRemaining() {
            return position < limit;
        }

        private BerElement readElementSafe() {
            try {
                return readElement();
            } catch (RuntimeException e) {
                return null;
            }
        }

        private BerElement readElement() {
            if (!hasRemaining()) {
                throw new IllegalStateException("No BER data remaining");
            }
            int tag = readUnsignedByte();
            int length = readLength();
            if (length < 0 || position + length > limit) {
                throw new IllegalStateException("Invalid BER length");
            }
            byte[] value = new byte[length];
            System.arraycopy(data, position, value, 0, length);
            position += length;
            return new BerElement(tag, value);
        }

        private int readUnsignedByte() {
            if (!hasRemaining()) {
                throw new IllegalStateException("Unexpected BER end");
            }
            return data[position++] & 0xFF;
        }

        private int readLength() {
            int first = readUnsignedByte();
            if ((first & 0x80) == 0) {
                return first;
            }
            int count = first & 0x7F;
            if (count == 0 || count > 4) {
                throw new IllegalStateException("Unsupported BER length form");
            }
            int length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | readUnsignedByte();
            }
            return length;
        }
    }
}
