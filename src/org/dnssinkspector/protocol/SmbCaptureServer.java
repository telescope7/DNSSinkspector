package org.dnssinkspector.protocol;

import java.io.IOException;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.dnssinkspector.config.SinkholeConfig.TcpServiceConfig;
import org.dnssinkspector.logging.EventLogger;

public final class SmbCaptureServer extends AbstractTcpCaptureServer {
    private static final byte[] NTLMSSP_SIGNATURE = "NTLMSSP\0".getBytes(StandardCharsets.US_ASCII);

    public SmbCaptureServer(TcpServiceConfig config, EventLogger eventLogger) {
        super("SMB", config, eventLogger);
    }

    @Override
    protected TcpSessionCapture captureSession(Socket socket) throws IOException {
        TcpCaptureUtil.ReadResult readResult = TcpCaptureUtil.readUpTo(
                socket.getInputStream(),
                getConfig().getCaptureMaxBytes());
        byte[] payload = readResult.payload();

        SmbParseResult parsed = parsePayload(payload);
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("smb_dialect", parsed.dialect);
        extra.put("smb_command", parsed.command);
        extra.put("smb_command_name", parsed.commandName);
        extra.put("smb_message_id", parsed.messageId);
        extra.put("smb_tree_id", parsed.treeId);
        extra.put("smb_session_id", parsed.sessionId);
        extra.put("ntlmssp_message_type", parsed.ntlmMessageType);
        extra.put("ntlmssp_username", parsed.ntlmUsername);
        extra.put("ntlmssp_domain", parsed.ntlmDomain);
        extra.put("ntlmssp_workstation", parsed.ntlmWorkstation);
        extra.put("ntlmssp_lm_response_len", parsed.ntlmLmResponseLength);
        extra.put("ntlmssp_nt_response_len", parsed.ntlmNtResponseLength);

        String decision;
        if (payload.length == 0) {
            decision = "captured_no_data_and_closed";
        } else if (readResult.truncated()) {
            decision = "captured_truncated_and_closed";
        } else if (parsed.ntlmMessageType != null) {
            decision = "captured_auth_material_and_closed";
        } else {
            decision = "captured_and_closed";
        }

        return new TcpSessionCapture(
                parsed.ntlmUsername,
                null,
                new String(payload, StandardCharsets.UTF_8),
                Base64.getEncoder().encodeToString(payload),
                payload.length,
                readResult.truncated(),
                decision,
                null,
                extra);
    }

    private static SmbParseResult parsePayload(byte[] payload) {
        SmbParseResult result = new SmbParseResult();
        int smbHeaderOffset = findSmbHeaderOffset(payload);
        if (smbHeaderOffset >= 0 && smbHeaderOffset + 4 <= payload.length) {
            int signature = u32be(payload, smbHeaderOffset);
            if (signature == 0xFE534D42) {
                parseSmb2Header(payload, smbHeaderOffset, result);
            } else if (signature == 0xFF534D42) {
                parseSmb1Header(payload, smbHeaderOffset, result);
            }
        }

        int ntlmOffset = indexOf(payload, NTLMSSP_SIGNATURE, 0);
        if (ntlmOffset >= 0) {
            parseNtlmMessage(payload, ntlmOffset, result);
        }

        return result;
    }

    private static int findSmbHeaderOffset(byte[] payload) {
        if (payload.length < 4) {
            return -1;
        }

        // SMB over NetBIOS Session Service.
        if ((payload[0] & 0xFF) == 0x00 && payload.length >= 8) {
            int length = ((payload[1] & 0xFF) << 16) | ((payload[2] & 0xFF) << 8) | (payload[3] & 0xFF);
            if (length > 0 && 4 + length <= payload.length) {
                return 4;
            }
        }

        int direct = indexOfSmbSignature(payload, 0);
        return direct;
    }

    private static void parseSmb2Header(byte[] payload, int offset, SmbParseResult result) {
        if (offset + 64 > payload.length) {
            result.dialect = "SMB2";
            return;
        }

        result.dialect = "SMB2";
        int command = u16le(payload, offset + 12);
        result.command = command;
        result.commandName = smb2CommandName(command);
        result.messageId = u64le(payload, offset + 24);
        result.treeId = u32le(payload, offset + 36);
        result.sessionId = u64le(payload, offset + 40);
    }

    private static void parseSmb1Header(byte[] payload, int offset, SmbParseResult result) {
        if (offset + 32 > payload.length) {
            result.dialect = "SMB1";
            return;
        }
        result.dialect = "SMB1";
        int command = payload[offset + 4] & 0xFF;
        result.command = command;
        result.commandName = smb1CommandName(command);
    }

    private static void parseNtlmMessage(byte[] payload, int ntlmOffset, SmbParseResult result) {
        if (ntlmOffset + 12 > payload.length) {
            return;
        }

        int messageType = u32le(payload, ntlmOffset + 8);
        result.ntlmMessageType = messageType;

        if (messageType != 3) {
            return;
        }

        int flags = readIntLeSafe(payload, ntlmOffset + 60);
        Charset textCharset = ((flags & 0x00000001) != 0)
                ? StandardCharsets.UTF_16LE
                : StandardCharsets.US_ASCII;

        SecurityBuffer lmResponse = readSecurityBuffer(payload, ntlmOffset + 12);
        SecurityBuffer ntResponse = readSecurityBuffer(payload, ntlmOffset + 20);
        SecurityBuffer domainName = readSecurityBuffer(payload, ntlmOffset + 28);
        SecurityBuffer userName = readSecurityBuffer(payload, ntlmOffset + 36);
        SecurityBuffer workstation = readSecurityBuffer(payload, ntlmOffset + 44);

        result.ntlmLmResponseLength = lmResponse == null ? null : lmResponse.length();
        result.ntlmNtResponseLength = ntResponse == null ? null : ntResponse.length();
        result.ntlmDomain = decodeSecurityBuffer(payload, domainName, ntlmOffset, textCharset);
        result.ntlmUsername = decodeSecurityBuffer(payload, userName, ntlmOffset, textCharset);
        result.ntlmWorkstation = decodeSecurityBuffer(payload, workstation, ntlmOffset, textCharset);
    }

    private static SecurityBuffer readSecurityBuffer(byte[] payload, int offset) {
        if (offset + 8 > payload.length) {
            return null;
        }
        int length = u16le(payload, offset);
        int dataOffset = u32le(payload, offset + 4);
        if (length < 0 || dataOffset < 0) {
            return null;
        }
        return new SecurityBuffer(length, dataOffset);
    }

    private static String decodeSecurityBuffer(byte[] payload, SecurityBuffer buffer, int baseOffset, Charset charset) {
        if (buffer == null || buffer.length() <= 0) {
            return null;
        }
        int start = baseOffset + buffer.offset();
        int end = start + buffer.length();
        if (start < 0 || end > payload.length || start >= end) {
            return null;
        }
        String value = new String(payload, start, buffer.length(), charset);
        return value.replace("\u0000", "");
    }

    private static String smb2CommandName(int command) {
        return switch (command) {
        case 0x0000 -> "NEGOTIATE";
        case 0x0001 -> "SESSION_SETUP";
        case 0x0002 -> "LOGOFF";
        case 0x0003 -> "TREE_CONNECT";
        case 0x0004 -> "TREE_DISCONNECT";
        case 0x0005 -> "CREATE";
        case 0x0006 -> "CLOSE";
        case 0x0007 -> "FLUSH";
        case 0x0008 -> "READ";
        case 0x0009 -> "WRITE";
        case 0x000A -> "LOCK";
        case 0x000B -> "IOCTL";
        case 0x000C -> "CANCEL";
        case 0x000D -> "ECHO";
        case 0x000E -> "QUERY_DIRECTORY";
        case 0x000F -> "CHANGE_NOTIFY";
        case 0x0010 -> "QUERY_INFO";
        case 0x0011 -> "SET_INFO";
        case 0x0012 -> "OPLOCK_BREAK";
        default -> "CMD_0x" + Integer.toHexString(command).toUpperCase(Locale.ROOT);
        };
    }

    private static String smb1CommandName(int command) {
        return switch (command) {
        case 0x72 -> "NEGOTIATE";
        case 0x73 -> "SESSION_SETUP_ANDX";
        case 0x75 -> "TREE_CONNECT_ANDX";
        case 0xA2 -> "NT_CREATE_ANDX";
        case 0x2E -> "READ_ANDX";
        case 0x2F -> "WRITE_ANDX";
        default -> "CMD_0x" + Integer.toHexString(command).toUpperCase(Locale.ROOT);
        };
    }

    private static int indexOfSmbSignature(byte[] payload, int start) {
        for (int i = Math.max(0, start); i + 4 <= payload.length; i++) {
            int signature = u32be(payload, i);
            if (signature == 0xFE534D42 || signature == 0xFF534D42) {
                return i;
            }
        }
        return -1;
    }

    private static int indexOf(byte[] payload, byte[] pattern, int start) {
        if (pattern.length == 0) {
            return -1;
        }
        for (int i = Math.max(0, start); i + pattern.length <= payload.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (payload[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    private static int readIntLeSafe(byte[] data, int offset) {
        if (offset + 4 > data.length) {
            return 0;
        }
        return u32le(data, offset);
    }

    private static int u16le(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    private static int u32le(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    private static long u64le(byte[] data, int offset) {
        return ((long) data[offset] & 0xFF)
                | (((long) data[offset + 1] & 0xFF) << 8)
                | (((long) data[offset + 2] & 0xFF) << 16)
                | (((long) data[offset + 3] & 0xFF) << 24)
                | (((long) data[offset + 4] & 0xFF) << 32)
                | (((long) data[offset + 5] & 0xFF) << 40)
                | (((long) data[offset + 6] & 0xFF) << 48)
                | (((long) data[offset + 7] & 0xFF) << 56);
    }

    private static int u32be(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    private record SecurityBuffer(int length, int offset) {
    }

    private static final class SmbParseResult {
        private String dialect;
        private Integer command;
        private String commandName;
        private Long messageId;
        private Integer treeId;
        private Long sessionId;
        private Integer ntlmMessageType;
        private String ntlmUsername;
        private String ntlmDomain;
        private String ntlmWorkstation;
        private Integer ntlmLmResponseLength;
        private Integer ntlmNtResponseLength;
    }
}
