package com.deltapunkt.start.ssl;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SavingTrustManager implements X509TrustManager
{
    private final X509TrustManager tm;

    private X509Certificate[] chain;


    SavingTrustManager(X509TrustManager tm)
    {
        this.tm = tm;
    }


    public X509Certificate[] getAcceptedIssuers()
    {
        return tm.getAcceptedIssuers();
//        throw new UnsupportedOperationException();
    }


    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        throw new UnsupportedOperationException();
    }


    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        int chainLength = chain != null ? chain.length:-1;
        System.out.println("checkServerTrusted chain.length=" + chainLength);
        this.chain = chain;
        tm.checkServerTrusted(chain, authType);
    }

    public X509Certificate[] getChain() {
        return chain;
    }

    public X509TrustManager getTm() {
        return tm;
    }
}
