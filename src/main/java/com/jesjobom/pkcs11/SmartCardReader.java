package com.jesjobom.pkcs11;

import java.security.InvalidParameterException;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstraction for smart card readers. Only needs read operations to get the
 * label from the certificate.
 *
 * @author jesjobom, modified by I.Kolchagov
 */
public abstract class SmartCardReader {

    private static final Logger LOGGER = LoggerFactory.getLogger(SmartCardReader.class);

    protected final List<String> libs;

    /**
     * Creates new instance of SmartCardReader using list of native libs,
     * provided by NativeLibsUtils.getAvailableLibs()
     *
     * @param libs mandatory parameter. At least one library must be available
     */
    public SmartCardReader(List<String> libs) {
        if (libs == null || libs.isEmpty()) {
            throw new InvalidParameterException("Need native libraries to access the smart card. Use 'com.jesjobom.pkcs11.NativeLibsUtils#getAvailableLibs()' to get them.");
        }
        this.libs = libs;
    }

    /**
     * PIN code is static and shared between instances
     *
     * @param args First argument is PIN code. It's one-time mandatory
     */
    public abstract void setPIN(String... args);

    /**
     * Returns the alias in keystore, as read by PKCS11 library.
     *
     * @return X509 certificate alias
     */
    public abstract String getLabel();
}
