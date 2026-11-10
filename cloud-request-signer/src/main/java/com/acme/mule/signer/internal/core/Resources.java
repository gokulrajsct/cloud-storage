package com.acme.mule.signer.internal.core;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Opens a keystore/truststore given either as a file path or as a classpath resource of the Mule app. */
final class Resources {

    private Resources() {
    }

    static InputStream open(String location) throws FileNotFoundException {
        Path p = Paths.get(location);
        if (Files.isRegularFile(p)) {
            return new FileInputStream(p.toFile());
        }
        String name = location.startsWith("/") ? location.substring(1) : location;
        ClassLoader[] loaders = {Thread.currentThread().getContextClassLoader(), Resources.class.getClassLoader()};
        for (ClassLoader cl : loaders) {
            if (cl != null) {
                InputStream in = cl.getResourceAsStream(name);
                if (in != null) {
                    return in;
                }
            }
        }
        throw new FileNotFoundException("'" + location + "' is neither a file nor a classpath resource");
    }
}
