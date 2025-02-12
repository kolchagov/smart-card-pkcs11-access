package com.jesjobom.pkcs11.sun;

import com.jesjobom.pkcs11.SmartCardReader;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.security.auth.login.LoginException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(SunReader.class);

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

        X509Certificate certificate = getCertificate();

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
    public X509Certificate getCertificate() throws RuntimeException {
        KeyStore ks = getKeystore();
        X509Certificate certificate;
        try {
            certificate = getCertificateFromKeystore(ks);
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
        libs.forEach((lib) -> {
            try {
                if (keystore == null) {
                    keystore = loadKeystore(lib);
                }
            } catch (Exception ex) {
                LOGGER.debug("Failed to load keystore with library " + lib + ". Will try with the next one if available.", ex);
            }
        });
        if (keystore == null) {
            throw new RuntimeException("None of the libraries found were able to load the keystore from the Smart Card.");
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

        //the follwing code will allow re-initialization of the card if it's been removed
        KeyStore.PasswordProtection pinProtection = new KeyStore.PasswordProtection(pin.toCharArray());
        KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", provider, pinProtection);
        KeyStore keyStore = null;
        try {
            keyStore = builder.getKeyStore();
        } catch (Exception ex) {
            //if we've got exception here, our card has been removed
            provider.logout();
            throw ex;
        }
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
        builder.append(LOGGER.isDebugEnabled() ? "true\n" : "false\n");
//        builder.append("removable=true\n");
        builder.append("library=");
        builder.append(lib).append('\n');
        return builder.toString();
    }

    /**
     * Loads the last certificate from the smart card. This method checks the
     * certificate validity and key usage. It returns only valid certificate
     * with private key suitable for signing
     *
     * @param keyStore
     * @return {@link X509Certificate}
     */
    private X509Certificate getCertificateFromKeystore(KeyStore keyStore) throws KeyStoreException {
        List<String> aliases = Collections.list(keyStore.aliases());
        X509Certificate certificate = null;

        for (String tmpAlias : aliases) {
            if (keyStore.isKeyEntry(tmpAlias)) {
                final Certificate tmpCert = keyStore.getCertificate(tmpAlias);
                boolean tmpAddAlias = true;
                if (tmpCert instanceof X509Certificate) {
                    final X509Certificate tmpX509 = (X509Certificate) tmpCert;
                    Date now = new Date();
                    final boolean isValid = now.before(tmpX509.getNotAfter())
                            && now.after(tmpX509.getNotBefore());
                    tmpAddAlias = isValid;
                    // check if the certificate is supposed to be
                    // used for digital signatures
                    final boolean keyUsage[] = tmpX509.getKeyUsage();
                    if (keyUsage != null && keyUsage.length > 0) {
                        // KeyUsage = BIT STRING {
                        // digitalSignature (0),
                        // nonRepudiation (1),
                        // keyEncipherment (2),
                        // dataEncipherment (3),
                        // keyAgreement (4),
                        // keyCertSign (5),
                        // cRLSign (6),
                        // encipherOnly (7),
                        // decipherOnly (8) }
                        if (!(keyUsage[0] || keyUsage[1])) {
                            LOGGER.info("Certificate not for signature" + tmpAlias);
                            tmpAddAlias = false;
                        }
                    }
                }
                if (tmpAddAlias) {
                    certificate = (X509Certificate) tmpCert;
                }
            }
        }

        if (certificate == null) {
            throw new IllegalStateException("Not possible to access the certificate "
                    + "from the smart card. Is it a PKCS11 initialized card?");
        }
        return certificate;
    }
}
