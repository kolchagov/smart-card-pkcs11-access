package com.jesjobom.pkcs11.sun;

import com.jesjobom.pkcs11.SmartCardReader;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import javax.security.auth.login.LoginException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sun.security.pkcs11.SunPKCS11;

/**
 * Smart card reader using Sun's implementation. On Windows x64, Java 7 needs to
 * be 32 bits. Java 8+ should be fine either on 32 or 64 bits. Java 7 does not
 * include Sun's implementation for 64 bits since it was not homologated.
 *
 * @author jesjobom
 * @author I.Kolchagov (modifications)
 */
public class SunReader extends SmartCardReader {

    private static final Logger LOGGER = LogManager.getLogger(SunReader.class);

    private static String pin;
    private static SunPKCS11 provider;
    private KeyStore keystore;

    public SunReader(List<String> libs) {
        super(libs);
    }

    /**
     * Required parameter0 is PIN to unlock the keystore
     *
     * @param args
     */
    @Override
    public void setPIN(String... args) {
        pin = args == null || args.length == 0 ? null : args[0];
    }

    @Override
    public String getLabel() {

        X509Certificate certificate = getLastCertificate();

        try {
            return getKeystore().getCertificateAlias(certificate);
        } catch (KeyStoreException ex) {
            LOGGER.info("Can't read alias for certificate (invalid key)");
        }
        return null;
    }

    /**
     * Shows if this instance has PIN set-up
     *
     * @return
     */
    public boolean isPinSet() {
        return pin != null;
    }

    /**
     * Returns the last found certificate from unlocked keystore
     *
     * @return
     * @throws RuntimeException
     */
    public X509Certificate getLastCertificate() throws RuntimeException {
        KeyStore ks = getKeystore();
        X509Certificate certificate;
        try {
            certificate = getLastCertificateFromKeystore(ks);
        } catch (KeyStoreException ex) {
            LOGGER.error("Error while trying to load the keystore", ex);
            throw new RuntimeException(ex);
        }
        return certificate;
    }

    /**
     * Unlocks PKCS11 keystore and returns it
     *
     * @return
     * @throws RuntimeException
     */
    public synchronized KeyStore getKeystore() throws RuntimeException {
        if (keystore == null) {
            libs.forEach((lib) -> {
                try {
                    keystore = loadKeystore(lib);
                } catch (Exception ex) {
                    LOGGER.debug("Failed to load keystore with library " + lib + ". Will try with the next one if available.", ex);
                }
            });
            if (keystore == null) {
                throw new RuntimeException("None of the libraries found were able to load the keystore from the Smart Card.");
            }
        }
        return keystore;
    }

    /**
     * Load the certificates from the smart card using a keystore. Actually the
     * Sun's implementation defined that these certificates can only be obtained
     * via a keystore and a PIN code.
     *
     * @param lib
     * @return {@link KeyStore}
     */
    private KeyStore loadKeystore(String lib) throws Exception {
        if (provider == null) {
            provider = new SunPKCS11(new ByteArrayInputStream(generatePkcs11Config(lib).getBytes()));
            Security.addProvider(provider);
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS11");
        keyStore.load(null, pin == null ? null : pin.toCharArray());
//        logout();
        return keyStore;
    }

    /**
     * Logout current provider. Closes the keystore, after that private key
     * cannot be read
     */
    public void logout() {
        try {
            provider.logout();
        } catch (LoginException ex) {
        }
    }

    /**
     * Config for the Sun's implementation of PKCS11
     *
     * @see
     * http://docs.oracle.com/javase/7/docs/technotes/guides/security/p11guide.html#Config
     *
     * @param lib
     * @return
     */
    private static String generatePkcs11Config(String lib) {
        StringBuilder builder = new StringBuilder();

        builder.append("name=SmartCard\n");
        builder.append("showInfo=");
        builder.append(LOGGER.getLevel().isLessSpecificThan(Level.DEBUG) ? "true\n" : "false\n");
        builder.append("library=");
        builder.append(lib).append('\n');
        return builder.toString();
    }

    /**
     * Loads the last certificate from the smart card. By last I mean the
     * certificate with longest chain. I supose that this will be the user's
     * certificate.
     *
     * @param keyStore
     * @return {@link X509Certificate}
     */
    private X509Certificate getLastCertificateFromKeystore(KeyStore keyStore) throws KeyStoreException {

        List<String> aliases = Collections.list(keyStore.aliases());
        X509Certificate certificate = null;
        int chainSize = 0;

        for (String aliase : aliases) {
//			if (!keyStore.isCertificateEntry(aliase)) {
//				continue;
//			}

            int size = keyStore.getCertificateChain(aliase).length;
            if (certificate == null || chainSize < size) {
                chainSize = size;
                certificate = (X509Certificate) keyStore.getCertificate(aliase);
            }
        }

        if (certificate == null) {
            throw new NullPointerException("Not possible to access the certificate from the smart card. Is it a PKCS11 initialized card?");
        }

        //certificate.checkValidity();
        return certificate;
    }
}
