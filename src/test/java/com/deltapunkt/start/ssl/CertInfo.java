package com.deltapunkt.start.ssl;

public class CertInfo {
    private int idx;
    private boolean trust;
    private boolean accept;
    private String subject;
    private String issuer;
    private String SHA1;
    private String MD5;

    public CertInfo(int idx, boolean trust, boolean accept, String subject, String issuer, String sha1, String md5) {
        this.idx = idx;
        this.trust = trust;
        this.accept = accept;
        this.subject = subject;
        this.issuer = issuer;
        SHA1 = sha1;
        MD5 = md5;
    }

    public int getIdx() {
        return idx;
    }

    public boolean isTrust() {
        return trust;
    }

    public boolean isAccept() {
        return accept;
    }

    public String getSubject() {
        return subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSHA1() {
        return SHA1;
    }

    public String getMD5() {
        return MD5;
    }

    @Override
    public String toString() {
        return "CertInfo{" +
                "idx=" + idx +
                ", trust=" + trust +
                ", accept=" + accept +
                ", subject='" + subject + '\'' +
                ", issuer='" + issuer + '\'' +
                ", SHA1='" + SHA1 + '\'' +
                ", MD5='" + MD5 + '\'' +
                '}';
    }
}
