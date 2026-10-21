// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.os.Process;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** Owned playback only. No Activity, recording or change to the foreground app. */
public final class AudioPlaybackInstrumentation extends Instrumentation {
    private String runId;
    @Override public void onCreate(Bundle args) {
        super.onCreate(args);runId=args==null?null:args.getString("run_id");
        if(runId==null || !runId.matches("[a-f0-9]{32}")) {finish(1,new Bundle());return;}
        start();
    }
    @Override public void onStart() {
        int code=1;
        try {
            Context context=getTargetContext();
            JSONObject report=new JSONObject().put("schema_version",1).put("probe","owned_android_hardware_v1")
                .put("package",context.getPackageName()).put("run_id",runId).put("uid",Process.myUid())
                .put("fingerprint",android.os.Build.FINGERPRINT).put("suite","audio_playback_pattern")
                .put("sensors",new JSONObject().put("status","not_requested"))
                .put("cameras",new JSONObject().put("status","not_requested"))
                .put("audio",AudioProbe.playPattern(context)).put("user_content_collected",false).put("full_port_verified",false);
            File temp=new File(context.getFilesDir(),"gb-"+runId+".tmp");
            try(FileOutputStream stream=new FileOutputStream(temp)) {stream.write(report.toString().getBytes(StandardCharsets.UTF_8));stream.getFD().sync();}
            if(!temp.renameTo(new File(context.getFilesDir(),"gb-"+runId+".json")))throw new IllegalStateException("publication failed");
            code=0;
        } catch(Throwable failure) { /* No arbitrary framework exception text or user data exported. */ }
        finally {finish(code,new Bundle());}
    }
}
