package org.googlebook.port.terminalprobe;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import android.system.Os;
import android.system.OsConstants;
import org.json.JSONObject;

/** Preserve the staged config/disks; publish a separate config for immutable boot inputs. */
final class ImmutableBootConfig {
    static File prepare(File original, JSONObject config, JSONObject manifest) throws Exception {
        String id=manifest.getString("id");
        if(!id.matches("[a-z0-9-]{1,64}"))throw new SecurityException("profile ID");
        Path profile=original.getParentFile().toPath().toRealPath();
        Path root=Paths.get("/system_ext/etc/gb-vm",id).toRealPath();
        for(String[] pair:new String[][]{{"kernel","guest-kernel.img"},{"initrd","initrd.img"}}) {
            Path old=profile.resolve(pair[1]);
            if(!config.getString(pair[0]).equals(old.toString()))
                throw new SecurityException("original boot path differs");
            Path immutable=root.resolve(pair[1]);
            if(!Files.isRegularFile(immutable,LinkOption.NOFOLLOW_LINKS)
                    || !immutable.toRealPath().equals(immutable)
                    || (Os.statvfs(immutable.toString()).f_flag & OsConstants.ST_RDONLY)==0)
                throw new SecurityException("boot source must be a read-only regular image file");
            JSONObject spec=manifest.getJSONObject("payloads").getJSONObject(pair[0]);
            for(Path input:new Path[]{old,immutable}) {
                RuntimeInspection.Fingerprint found=RuntimeInspection.fingerprint(input);
                if(found.bytes!=spec.getLong("bytes") || !found.sha256.equals(spec.getString("sha256")))
                    throw new SecurityException("boot file bytes differ from pinned profile: "+pair[0]);
            }
            config.put(pair[0],immutable.toString());
        }
        byte[] bytes=config.toString(2).getBytes(StandardCharsets.UTF_8);
        if(bytes.length>65536)throw new IOException("config bound");
        String hash=PayloadReceiver.hex(MessageDigest.getInstance("SHA-256").digest(bytes));
        Path destination=profile.resolve("vm_config.immutable-boot-"+hash+".json");
        try(FileChannel out=FileChannel.open(destination,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)) {
            ByteBuffer buffer=ByteBuffer.wrap(bytes);while(buffer.hasRemaining())out.write(buffer);out.force(true);
        } catch(FileAlreadyExistsException exists) {
            if(!Files.isRegularFile(destination,LinkOption.NOFOLLOW_LINKS)
                    || Files.size(destination)!=bytes.length
                    || !RuntimeInspection.fingerprint(destination).sha256.equals(hash))
                throw new IOException("existing immutable config differs",exists);
        }
        return destination.toFile();
    }
}
