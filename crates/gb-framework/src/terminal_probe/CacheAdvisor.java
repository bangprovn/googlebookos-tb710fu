package org.googlebook.port.terminalprobe;
import android.content.Context;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.json.*;

/** Runs only an explicitly pinned owner-built ELF from APK's read-only native directory. */
public final class CacheAdvisor {
    public static void advise(Context context, String sha256, File directory,
            Map<String,PayloadReceiver.Item> items) throws Exception {
        if (!sha256.matches("[0-9a-f]{64}")) throw new SecurityException("cache advisor digest");
        File binary=new File(context.getApplicationInfo().nativeLibraryDir,"libgb_cache_advisor.so");
        if (!binary.isFile() || binary.length()>2*1024*1024) throw new IOException("native advisor missing or oversized");
        MessageDigest hash=MessageDigest.getInstance("SHA-256");
        try(InputStream in=new FileInputStream(binary)) {
            byte[] buffer=new byte[8192];int n;
            while((n=in.read(buffer))>=0)hash.update(buffer,0,n);
        }
        if(!PayloadReceiver.hex(hash.digest()).equals(sha256))throw new SecurityException("native advisor identity");
        for(PayloadReceiver.Item item:items.values()) {
            File file=new File(directory,item.filename);
            Process child=new ProcessBuilder(binary.getAbsolutePath(),file.getAbsolutePath(),Long.toString(item.bytes))
                .redirectErrorStream(true).start();
            if(!child.waitFor(30,TimeUnit.SECONDS)) {child.destroyForcibly();throw new IOException("cache advisor deadline");}
            ByteArrayOutputStream output=new ByteArrayOutputStream();
            try(InputStream in=child.getInputStream()) {
                byte[] bytes=new byte[1024];int n;
                while((n=in.read(bytes))>=0) {if(output.size()+n>65536)throw new IOException("cache receipt limit");output.write(bytes,0,n);}
            }
            String text=new String(output.toByteArray(),"UTF-8");
            if(child.exitValue()!=0)throw new IOException("cache advisor failed: "+text);
            JSONObject receipt=new JSONObject(text);
            if(!receipt.getString("status").equals("owned_file_cache_hint_submitted")
                    || receipt.getBoolean("contents_changed") || receipt.getLong("file_bytes")!=item.bytes)
                throw new IOException("invalid cache receipt");
        }
    }
}
