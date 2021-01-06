package com.jesjobom.pkcs11.utils;

import com.sun.jna.Platform;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper to find smart card native librabies in the OS. Actually using a list
 * of known possible libs (.so or .dll).
 *
 * @author jesjobom
 */
public class NativeLibsUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(NativeLibsUtils.class);

    private static final String WIN_BASE = "C:/Windows/System32/";
    private static final String UNIX_BASE = "/usr/lib/";
    private static final String MACOS_BASE = "/Library/Security/tokend/";

    private static final String[] WIN_LIBS = {"idprimepkcs11.dll", "aetpkss1.dll", "asepkcs.dll", "gclib.dll", "pk2priv.dll", "w32pk2ig.dll", "ngp11v211.dll", "eTPkcs11.dll", "eTPKCS11.dll", "acospkcs11.dll", "dkck201.dll", "dkck232.dll", "cryptoki22.dll", "acpkcs.dll", "slbck.dll", "WDPKCS.dll", "cmP11.dll", "WDBraz_P11_CCID_v34.dll", "cvP11.dll"};
    private static final String[] UNIX_LIBS = {"libASEP11.so", "opensc-pkcs11.so", "libaetpkss.so", "libaetpkss.so.3", "libgpkcs11.so", "libgpkcs11.so.2", "libepsng_p11.so", "libepsng_p11.so.1", "libeTPkcs11.so", "libeToken.so", "libeToken.so.4", "libcmP11.so", "libwdpkcs.so", "/usr/local/lib64/libwdpkcs.so", "/usr/local/lib/libwdpkcs.so", "pkcs11/opensc-pkcs11.so", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", "ifdokccid.so", "libokbase2.so", "libokbase2.so.3"};

    /**
     * Search for available native libraries and returns list with available
     * ones
     *
     * @return
     */
    public static List<String> getAvailableLibs() {
        LOGGER.debug("Detected OS: " + OsUtils.getOsName());

        List<String> foundLibs;
        if (OsUtils.isWindows()) {
            foundLibs = findLibs(false, WIN_BASE, WIN_LIBS);
        } else if (Platform.isMac()) {
            foundLibs = findLibs(true, MACOS_BASE, UNIX_LIBS);
        } else {
            foundLibs = findLibs(false, UNIX_BASE, UNIX_LIBS);
        }

        LOGGER.debug((foundLibs == null ? 0 : foundLibs.size()) + " libs found.");
        return foundLibs;
    }

    /**
     * Search for installed hardware token libaries
     *
     * @param isMacOS if true it will scan subfolders and replace .so extension
     * with .dylib
     * @param basePath
     * @param libs
     * @return
     */
    private static List<String> findLibs(boolean isMacOS, String basePath, String... libs) {
        List<String> foundLibs = new ArrayList<>();
        if (isMacOS) {
            File[] files = new File(basePath).listFiles();
            for (File file : files) {
                if (file.isDirectory()) {
                    final List<String> others = findLibs(
                            isMacOS, String.format("%s/%s/", basePath, file.getName()), libs);
                    foundLibs.addAll(others);
                }
            }
        }
        for (String lib : libs) {
            File file;
            lib = isMacOS ? lib.replace(".so", ".dylib") : lib;
            if (lib.startsWith("/") || lib.startsWith("C:")) {
                file = new File(lib);
            } else {
                file = new File(basePath + lib);
            }
            if (file.exists()) {
                foundLibs.add(file.getAbsolutePath());
                LOGGER.debug("Found lib: " + file.getAbsolutePath());
            }
        }
        return foundLibs;
    }
}
