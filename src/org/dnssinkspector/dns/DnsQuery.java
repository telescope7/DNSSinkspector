package org.dnssinkspector.dns;

public final class DnsQuery {
    private final int transactionId;
    private final int flags;
    private final String qname;
    private final int qtype;
    private final int qclass;

    public DnsQuery(int transactionId, int flags, String qname, int qtype, int qclass) {
        this.transactionId = transactionId;
        this.flags = flags;
        this.qname = qname;
        this.qtype = qtype;
        this.qclass = qclass;
    }

    public int getTransactionId() {
        return transactionId;
    }

    public int getFlags() {
        return flags;
    }

    public String getQname() {
        return qname;
    }

    public int getQtype() {
        return qtype;
    }

    public int getQclass() {
        return qclass;
    }

    public boolean isRecursionDesired() {
        return (flags & 0x0100) != 0;
    }
}
