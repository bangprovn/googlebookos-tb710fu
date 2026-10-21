package org.googlebook.port.terminalprobe;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Fixed read-only observations; never execute a VMM or inspect app-private files. */
final class RuntimeInspection {
    private static final long MAX_BINARY_BYTES = 64L * 1024 * 1024;
    static final class Fingerprint {
        final long bytes;
        final String sha256;
        Fingerprint(long bytes, String sha256) { this.bytes=bytes; this.sha256=sha256; }
    }
    static Fingerprint fingerprint(Path path) throws Exception {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("not a regular non-symlink file");
        try (FileChannel file = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            long size=file.size();
            if (size<=0 || size>MAX_BINARY_BYTES) throw new IOException("binary size outside inspection bound");
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            ByteBuffer buffer=ByteBuffer.allocate(8192); long total=0; int n;
            while ((n=file.read(buffer))!=-1) {
                if (n>MAX_BINARY_BYTES-total) throw new IOException("binary grew beyond inspection bound");
                total+=n; buffer.flip(); digest.update(buffer); buffer.clear();
            }
            if (total!=size || file.size()!=size) throw new IOException("binary changed during inspection");
            StringBuilder hex=new StringBuilder(64);
            for (byte value : digest.digest()) hex.append(String.format(Locale.ROOT,"%02x",value & 255));
            return new Fingerprint(total,hex.toString());
        }
    }
    private static String error(Exception error) {
        String text=error.getClass().getSimpleName()+": "+String.valueOf(error.getMessage());
        return text.substring(0,Math.min(240,text.length())).replace('\n',' ').replace('\r',' ');
    }
    static Map<String,String> collect() {
        Map<String,String> result=new LinkedHashMap<>();
        try (InputStream in = new FileInputStream("/proc/self/attr/current")) {
            ByteArrayOutputStream out=new ByteArrayOutputStream(); byte[] block=new byte[256]; int n;
            while ((n=in.read(block))!=-1) {
                if (out.size()+n>1024) throw new IOException("process context exceeds bound");
                out.write(block,0,n);
            }
            result.put("target_selinux_context",new String(out.toByteArray(),StandardCharsets.UTF_8).trim());
        } catch (Exception e) { result.put("target_selinux_context_error",error(e)); }
        for (String[] entry : new String[][]{{"crosvm","crosvm"},
                {"crosvm_minimal","crosvm_minimal"},{"gb-crosvm-real","retained_crosvm"}}) {
            String name=entry[0], key="runtime_"+entry[1];
            try {
                Fingerprint file=fingerprint(Paths.get("/apex/com.android.virt/bin/"+name));
                result.put(key+"_sha256",file.sha256);
                result.put(key+"_bytes",Long.toString(file.bytes));
            } catch (Exception e) { result.put(key+"_error",error(e)); }
        }
        return result;
    }
}
