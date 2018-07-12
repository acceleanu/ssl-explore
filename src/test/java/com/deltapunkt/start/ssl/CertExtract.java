package com.deltapunkt.start.ssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toList;

public class CertExtract {
    public static void extract(String host, int port, String passphrase) {
        try {
            KeyStore ks = getKeyStore(passphrase);

            SSLContext context = SSLContext.getInstance("TLS");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            TrustManager[] trustManagers = tmf.getTrustManagers();
            X509TrustManager defaultTrustManager = (X509TrustManager) trustManagers[0];
            List<X509Certificate> rootCertificates = asList(defaultTrustManager.getAcceptedIssuers());

            System.out.println("--------------------------");
            System.out.println("Root Certificates:");
            List<String> rootNames = rootCertificates.stream()
                    .map(ai -> ai.getIssuerDN().getName())
                    .collect(toList());
            rootNames.forEach(System.out::println);
            System.out.println("--------------------------");

            SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
            context.init(null, new TrustManager[]{tm}, null);
            SSLSocketFactory factory = context.getSocketFactory();

            Util.log("Opening connection to " + host + ":" + port + "...\n");
            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(10000);
            try {
                Util.log("Starting SSL handshake ...\n");
                socket.startHandshake();
                socket.close();
                Util.log("No errors, certificate is already trusted\n");
            } catch (SSLException exc) {
                exc.printStackTrace();
                Util.log(exc.getMessage() + "\n");
            }

            X509Certificate[] chain = tm.getChain();
            if (chain == null) {
                Util.log("Could not obtain server certificate chain\n");
                return;
            }

            Util.log("Server sent " + chain.length + " certificate(s)\n");
            List<CertInfo> certs = new ArrayList<>();

            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = chain[i];

                boolean trusted = false;

                for (int j = i; j >= 0; j--)
                {
                    if (rootNames.contains(chain[j].getIssuerDN().getName()))
                    {
                        trusted = true;
                        break;
                    }
                }

                sha1.update(cert.getEncoded());
                md5.update(cert.getEncoded());

                CertInfo certInfo = new CertInfo(
                        i + 1,
                        trusted,
                        trusted,
                        cert.getSubjectDN().toString(),
                        cert.getIssuerDN().toString(),
                        Util.toHexString(sha1.digest()),
                        Util.toHexString(md5.digest())
                );
                certs.add(certInfo);
            }
            certs.forEach(System.out::println);
        } catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private static KeyStore getKeyStore(String passphrase) throws Exception {
        File file = new File("jssecacerts");
        if (!file.isFile()) {
            File dir = new File(new File(System.getProperty("java.home"), "lib"), "security");
            file = new File(dir, "jssecacerts");
            if (!file.isFile()) {
                file = new File(dir, "cacerts");
            }
        }
        Util.log("Loading KeyStore " + file + "...\n");
        InputStream in = new FileInputStream(file);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(in, passphrase.toCharArray());
        in.close();
        return ks;
    }

    public static void addCertificateToStore(KeyStore ks, X509Certificate cert, String alias, String passphrase) {
        try
        {
            ks.setCertificateEntry(alias, cert);
            OutputStream out = new BufferedOutputStream(new FileOutputStream("jssecacerts"));
            ks.store(out, passphrase.toCharArray());
            out.close();
        } catch (Exception e)
        {
            e.printStackTrace();
        }
        Util.log("Added certificate to keystore './jssecacerts' using alias '" + alias + "'");
    }

    public static void main(String[] args) {
//        extract("github.com", 443, "changeit");
//        extract("self-signed.badssl.com", 443, "changeit");
        extract("hsts.badssl.com", 443, "changeit");
        //https://github.com/chromium/badssl.com.git
    }
}
