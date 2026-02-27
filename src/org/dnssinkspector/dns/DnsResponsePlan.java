package org.dnssinkspector.dns;

import java.net.Inet4Address;
import java.util.List;

public final class DnsResponsePlan {
    public static final int RCODE_NOERROR = 0;
    public static final int RCODE_FORMERR = 1;
    public static final int RCODE_NXDOMAIN = 3;

    private final int rcode;
    private final List<Inet4Address> answerIpv4;
    private final int ttlSeconds;
    private final String decision;

    private DnsResponsePlan(int rcode, List<Inet4Address> answerIpv4, int ttlSeconds, String decision) {
        this.rcode = rcode;
        this.answerIpv4 = List.copyOf(answerIpv4);
        this.ttlSeconds = ttlSeconds;
        this.decision = decision;
    }

    public static DnsResponsePlan matchedZone(List<Inet4Address> answerIpv4, int ttlSeconds) {
        return new DnsResponsePlan(RCODE_NOERROR, answerIpv4, ttlSeconds, "matched_zone");
    }

    public static DnsResponsePlan noData(String decision) {
        return new DnsResponsePlan(RCODE_NOERROR, List.of(), 0, decision);
    }

    public static DnsResponsePlan nxdomain(String decision) {
        return new DnsResponsePlan(RCODE_NXDOMAIN, List.of(), 0, decision);
    }

    public static DnsResponsePlan formerr(String decision) {
        return new DnsResponsePlan(RCODE_FORMERR, List.of(), 0, decision);
    }

    public int getRcode() {
        return rcode;
    }

    public List<Inet4Address> getAnswerIpv4() {
        return answerIpv4;
    }

    public int getTtlSeconds() {
        return ttlSeconds;
    }

    public String getDecision() {
        return decision;
    }
}
