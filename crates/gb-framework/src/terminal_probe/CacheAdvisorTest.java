package org.googlebook.port.terminalprobe;
import android.content.*;
import android.util.Log;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.json.*;

/** DUMP-protected, direct-boot-safe test using only this helper's own new fixture. */
public final class CacheAdvisorTest extends BroadcastReceiver {
    @Override public void onReceive(final Context context,Intent intent) {
        final PendingResult result=goAsync();
        new Thread(new Runnable() { @Override public void run() {
            Path directory=null;
            try {
                byte[] data="owner cache advice fixture".getBytes("UTF-8");
                Context storage=context.createDeviceProtectedStorageContext();
                directory=Files.createTempDirectory(storage.getFilesDir().toPath(),"cache-advice-");
                File file=directory.resolve("fixture.img").toFile();
                try(FileOutputStream out=new FileOutputStream(file)) {out.write(data);out.getFD().sync();}
                String sha=PayloadReceiver.hex(MessageDigest.getInstance("SHA-256").digest(data));
                ByteArrayOutputStream bytes=new ByteArrayOutputStream();
                try(InputStream in=context.getAssets().open("payload-manifest.json")) {
                    byte[] b=new byte[4096];int n;while((n=in.read(b))>=0) {if(bytes.size()+n>65536)throw new IOException("manifest limit");bytes.write(b,0,n);}
                }
                JSONObject manifest=new JSONObject(new String(bytes.toByteArray(),"UTF-8"));
                CacheAdvisor.advise(context,manifest.getString("cache_advisor_sha256"),directory.toFile(),
                    Collections.singletonMap("fixture",new PayloadReceiver.Item("fixture.img",data.length,sha)));
                if(!Arrays.equals(Files.readAllBytes(file.toPath()),data))throw new IOException("fixture changed");
                result.setResultCode(-1);result.setResultData("{\"status\":\"passed\",\"fixture_unchanged\":true}");
                Log.i("GbCacheAdvisorTest","PASS: native advisor executes under app UID "+android.os.Process.myUid()+"; owned fixture unchanged");
            } catch(Exception error) {
                result.setResultCode(0);result.setResultData("failed: "+error.getClass().getSimpleName()+": "+error.getMessage());Log.e("GbCacheAdvisorTest","FAIL",error);
            } finally {
                if(directory!=null) {try {Files.deleteIfExists(directory.resolve("fixture.img"));Files.deleteIfExists(directory);}catch(IOException ignored){}}
                result.finish();
            }
        } },"gb-cache-advisor-test").start();
    }
}
