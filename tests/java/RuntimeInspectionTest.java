package org.googlebook.port.terminalprobe;

import java.nio.file.*;

/** Runs only owner-built Java on host-owned fixtures, never firmware code. */
public final class RuntimeInspectionTest {
    private static void rejects(Path path) throws Exception {
        try {
            RuntimeInspection.fingerprint(path);
            throw new AssertionError("accepted unsafe fixture: "+path.getFileName());
        } catch (java.io.IOException expected) { }
    }
    public static void main(String[] args) throws Exception {
        Path root=Paths.get(args[0]);
        RuntimeInspection.Fingerprint valid=RuntimeInspection.fingerprint(root.resolve("regular"));
        if (!valid.sha256.equals(args[1]) || valid.bytes!=1048613)
            throw new AssertionError("streamed fingerprint differs from independent fixture hash");
        for (String name : new String[]{"empty","oversized","link","directory","fifo","missing"})
            rejects(root.resolve(name));
        System.out.println("PASS: bounded regular-file fingerprint; empty, oversized, symlink, directory, FIFO and missing inputs rejected");
    }
}
