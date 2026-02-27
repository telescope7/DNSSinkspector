package org.dnssinkspector.protocol;

public final class TcpSessionCapture {
    private final String username;
    private final String password;
    private final String dataText;
    private final String dataBase64;
    private final int bytesCaptured;
    private final boolean truncated;
    private final String decision;
    private final String error;

    public TcpSessionCapture(
            String username,
            String password,
            String dataText,
            String dataBase64,
            int bytesCaptured,
            boolean truncated,
            String decision,
            String error) {
        this.username = username;
        this.password = password;
        this.dataText = dataText;
        this.dataBase64 = dataBase64;
        this.bytesCaptured = bytesCaptured;
        this.truncated = truncated;
        this.decision = decision;
        this.error = error;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getDataText() {
        return dataText;
    }

    public String getDataBase64() {
        return dataBase64;
    }

    public int getBytesCaptured() {
        return bytesCaptured;
    }

    public boolean isTruncated() {
        return truncated;
    }

    public String getDecision() {
        return decision;
    }

    public String getError() {
        return error;
    }
}
