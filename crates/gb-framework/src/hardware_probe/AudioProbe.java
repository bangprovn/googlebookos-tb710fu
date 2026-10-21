// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.media.AudioAttributes;
import android.media.AudioDeviceInfo;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioRecordingConfiguration;
import android.media.AudioTrack;
import android.media.MediaRecorder;
import android.os.SystemClock;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

/** Quiet known-pattern speaker/microphone test; buffers stay in RAM and are cleared. */
public final class AudioProbe {
    private static final int RATE=48000;
    private static void require(boolean ok) {if(!ok) throw new IllegalStateException("audio assertion failed");}
    private static AudioDeviceInfo builtin(AudioManager manager,int flags,int type) {
        for(AudioDeviceInfo device:manager.getDevices(flags)) if(device.getType()==type) return device;
        return null;
    }
    /** Playback only, for independent guest microphone tests without taking foreground focus. */
    public static JSONObject playPattern(Context context) throws Exception {
        JSONObject result=new JSONObject().put("state","unknown").put("phase","formats")
            .put("scope","Quiet generated pattern playback only; external capture must be independently verified")
            .put("local_recording_created",false).put("system_volume_changed",false)
            .put("sample_rate",RATE).put("channels",1).put("track_gain",0.08);
        short[] signal=AudioPattern.generate(RATE);AudioTrack track=null;
        try {
            AudioManager manager=(AudioManager)context.getSystemService(Context.AUDIO_SERVICE);require(manager!=null);
            int volume=manager.getStreamVolume(AudioManager.STREAM_MUSIC);result.put("media_volume",volume);
            AudioDeviceInfo speaker=builtin(manager,AudioManager.GET_DEVICES_OUTPUTS,AudioDeviceInfo.TYPE_BUILTIN_SPEAKER);require(speaker!=null);
            AudioFormat format=new AudioFormat.Builder().setSampleRate(RATE).setEncoding(AudioFormat.ENCODING_PCM_16BIT).setChannelMask(AudioFormat.CHANNEL_OUT_MONO).build();
            track=new AudioTrack.Builder().setAudioAttributes(new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA).setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build())
                .setAudioFormat(format).setTransferMode(AudioTrack.MODE_STATIC).setBufferSizeInBytes(signal.length*2).build();
            require(track.setVolume(0.08f)==AudioTrack.SUCCESS && track.setPreferredDevice(speaker));
            require(track.write(signal,0,signal.length)==signal.length);track.play();
            long deadline=SystemClock.elapsedRealtime()+2500;AudioDeviceInfo routed=null;
            while(track.getPlaybackHeadPosition()<signal.length && SystemClock.elapsedRealtime()<deadline) {
                if(routed==null)routed=track.getRoutedDevice();Thread.sleep(5);
            }
            int head=track.getPlaybackHeadPosition(),volumeAfter=manager.getStreamVolume(AudioManager.STREAM_MUSIC);
            boolean speakerVerified=routed!=null && routed.getType()==AudioDeviceInfo.TYPE_BUILTIN_SPEAKER;
            result.put("phase","playback_observed").put("playback_head_frames",head).put("written_playback_frames",signal.length)
                .put("output_device_type",routed==null?0:routed.getType()).put("builtin_speaker_verified",speakerVerified)
                .put("media_volume_after",volumeAfter).put("state",head>=signal.length && speakerVerified && volume==volumeAfter?"compatible":"unknown");
        } catch(Throwable failure) {result.put("error_class",failure.getClass().getName());}
        finally {try {if(track!=null) {try{track.stop();}catch(Throwable ignored){}track.release();}}finally{Arrays.fill(signal,(short)0);}}
        return new JSONObject().put("status","observed").put("results",new JSONArray().put(result));
    }
    /** Capture only: the caller must independently establish the external pattern's origin. */
    public static JSONObject capturePattern(Context context,Runnable ready) throws Exception {
        JSONObject result=new JSONObject().put("state","unknown").put("phase","permission")
            .put("scope","External ordered-pattern capture only; source identity and guest playback must be independently verified")
            .put("local_playback_created",false).put("raw_audio_saved_or_exported",false)
            .put("system_volume_changed",false).put("sample_rate",RATE).put("channels",1);
        AudioRecord record=null;short[] captured=new short[RATE*3];
        try {
            require(context.checkSelfPermission(Manifest.permission.RECORD_AUDIO)==PackageManager.PERMISSION_GRANTED);
            AudioManager manager=(AudioManager)context.getSystemService(Context.AUDIO_SERVICE);require(manager!=null);
            int volume=manager.getStreamVolume(AudioManager.STREAM_MUSIC);result.put("media_volume",volume);
            int minimum=AudioRecord.getMinBufferSize(RATE,AudioFormat.CHANNEL_IN_MONO,AudioFormat.ENCODING_PCM_16BIT);
            require(minimum>0 && minimum<=RATE*2);
            AudioFormat input=new AudioFormat.Builder().setSampleRate(RATE).setEncoding(AudioFormat.ENCODING_PCM_16BIT).setChannelMask(AudioFormat.CHANNEL_IN_MONO).build();
            record=new AudioRecord.Builder().setAudioSource(MediaRecorder.AudioSource.MIC).setAudioFormat(input).setBufferSizeInBytes(Math.max(16384,minimum)).build();
            require(record.getState()==AudioRecord.STATE_INITIALIZED);
            AudioDeviceInfo microphone=builtin(manager,AudioManager.GET_DEVICES_INPUTS,AudioDeviceInfo.TYPE_BUILTIN_MIC);
            require(microphone!=null);
            result.put("preferred_microphone_accepted",record.setPreferredDevice(microphone));
            record.startRecording();require(record.getRecordingState()==AudioRecord.RECORDSTATE_RECORDING);
            int count=0;boolean published=false;long start=SystemClock.elapsedRealtime();AudioDeviceInfo routed=null;
            while(count<captured.length && SystemClock.elapsedRealtime()-start<4000) {
                if(routed==null) routed=record.getRoutedDevice();
                int n=record.read(captured,count,Math.min(4096,captured.length-count),AudioRecord.READ_NON_BLOCKING);
                require(n>=0);count+=n;
                if(!published && count>=RATE/4) {
                    result.put("capture_warmup_frames",count);ready.run();published=true;
                }
                if(n==0)Thread.sleep(5);
            }
            AudioRecordingConfiguration configuration=record.getActiveRecordingConfiguration();
            boolean notSilenced=configuration!=null && !configuration.isClientSilenced();
            boolean builtinMic=routed!=null && routed.getType()==AudioDeviceInfo.TYPE_BUILTIN_MIC;
            AudioPattern.Detection detection=AudioPattern.detect(captured,count,RATE);
            int volumeAfter=manager.getStreamVolume(AudioManager.STREAM_MUSIC);
            result.put("phase","capture_observed").put("captured_frames",count)
                .put("digital_capture_flow_verified",count>=RATE).put("builtin_microphone_verified",builtinMic)
                .put("input_device_type",routed==null?0:routed.getType())
                .put("recording_configuration_available",configuration!=null).put("client_not_silenced",notSilenced)
                .put("known_acoustic_pattern_detected",detection.matched).put("strong_pattern_windows",detection.strongWindows)
                .put("analysed_windows",detection.totalWindows).put("media_volume_after",volumeAfter)
                .put("state",count>=RATE && builtinMic && notSilenced && detection.matched && volume==volumeAfter?"compatible":"unknown");
        } catch(Throwable failure) {result.put("error_class",failure.getClass().getName());}
        finally {
            try {if(record!=null) {try {record.stop();}catch(Throwable ignored){}record.release();}}
            finally {Arrays.fill(captured,(short)0);}
        }
        return new JSONObject().put("status","observed").put("results",new JSONArray().put(result));
    }
    public static JSONObject run(Context context) throws Exception {
        JSONObject result=new JSONObject().put("state","unknown").put("phase","permission")
            .put("scope","Quiet 640 ms known-pattern response on built-in speaker/microphone; not fidelity, microphone-array, headset, call or guest audio qualification")
            .put("raw_audio_saved_or_exported",false).put("system_volume_changed",false)
            .put("sample_rate",RATE).put("channels",1).put("track_gain",0.08);
        AudioRecord record=null;AudioTrack track=null;
        short[] captured=new short[RATE*2],signal=AudioPattern.generate(RATE);
        try {
            require(context.checkSelfPermission(Manifest.permission.RECORD_AUDIO)==PackageManager.PERMISSION_GRANTED);
            AudioManager manager=(AudioManager)context.getSystemService(Context.AUDIO_SERVICE);require(manager!=null);
            result.put("media_volume",manager.getStreamVolume(AudioManager.STREAM_MUSIC));
            result.put("phase","formats");
            int minimum=AudioRecord.getMinBufferSize(RATE,AudioFormat.CHANNEL_IN_MONO,AudioFormat.ENCODING_PCM_16BIT);
            require(minimum>0 && minimum<=RATE*2);
            AudioFormat input=new AudioFormat.Builder().setSampleRate(RATE).setEncoding(AudioFormat.ENCODING_PCM_16BIT).setChannelMask(AudioFormat.CHANNEL_IN_MONO).build();
            AudioFormat output=new AudioFormat.Builder().setSampleRate(RATE).setEncoding(AudioFormat.ENCODING_PCM_16BIT).setChannelMask(AudioFormat.CHANNEL_OUT_MONO).build();
            record=new AudioRecord.Builder().setAudioSource(MediaRecorder.AudioSource.MIC).setAudioFormat(input).setBufferSizeInBytes(Math.max(16384,minimum)).build();
            track=new AudioTrack.Builder().setAudioAttributes(new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA).setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build())
                .setAudioFormat(output).setTransferMode(AudioTrack.MODE_STATIC).setBufferSizeInBytes(signal.length*2).build();
            require(record.getState()==AudioRecord.STATE_INITIALIZED && track.getState()!=AudioTrack.STATE_UNINITIALIZED);
            AudioDeviceInfo speaker=builtin(manager,AudioManager.GET_DEVICES_OUTPUTS,AudioDeviceInfo.TYPE_BUILTIN_SPEAKER);
            AudioDeviceInfo microphone=builtin(manager,AudioManager.GET_DEVICES_INPUTS,AudioDeviceInfo.TYPE_BUILTIN_MIC);
            require(speaker!=null && microphone!=null);
            result.put("preferred_speaker_accepted",track.setPreferredDevice(speaker));
            result.put("preferred_microphone_accepted",record.setPreferredDevice(microphone));
            require(track.setVolume(0.08f)==AudioTrack.SUCCESS);
            require(track.write(signal,0,signal.length)==signal.length);
            result.put("phase","stream_start");
            record.startRecording();
            require(record.getRecordingState()==AudioRecord.RECORDSTATE_RECORDING);
            int count=0;long start=SystemClock.elapsedRealtime();boolean playing=false;
            AudioDeviceInfo observedOutput=null,observedInput=null;
            while(count<captured.length && SystemClock.elapsedRealtime()-start<3000) {
                if(!playing && SystemClock.elapsedRealtime()-start>=120) {track.play();playing=true;}
                if(playing) {
                    if(observedOutput==null) observedOutput=track.getRoutedDevice();
                    if(observedInput==null) observedInput=record.getRoutedDevice();
                }
                int n=record.read(captured,count,Math.min(4096,captured.length-count),AudioRecord.READ_NON_BLOCKING);
                require(n>=0);
                count+=n;
                if(n==0) Thread.sleep(5);
            }
            result.put("phase","stream_observed");
            int head=track.getPlaybackHeadPosition();
            // getRoutedDevice is valid during playback, not after a static clip ends.
            AudioDeviceInfo out=observedOutput,in=observedInput;
            AudioRecordingConfiguration configuration=record.getActiveRecordingConfiguration();
            boolean notSilenced=configuration!=null && !configuration.isClientSilenced();
            AudioPattern.Detection detection=AudioPattern.detect(captured,count,RATE);
            boolean playback=head>=signal.length,capture=count>=RATE;
            boolean builtinRoutes=out!=null && in!=null && out.getType()==AudioDeviceInfo.TYPE_BUILTIN_SPEAKER && in.getType()==AudioDeviceInfo.TYPE_BUILTIN_MIC;
            result.put("written_playback_frames",signal.length).put("playback_head_frames",head)
                .put("media_volume_after",manager.getStreamVolume(AudioManager.STREAM_MUSIC))
                .put("captured_frames",count).put("digital_playback_flow_verified",playback)
                .put("digital_capture_flow_verified",capture).put("builtin_routes_verified",builtinRoutes)
                .put("output_device_type",out==null?0:out.getType()).put("input_device_type",in==null?0:in.getType())
                .put("recording_configuration_available",configuration!=null).put("client_not_silenced",notSilenced)
                .put("known_acoustic_pattern_detected",detection.matched)
                .put("strong_pattern_windows",detection.strongWindows).put("analysed_windows",detection.totalWindows);
            boolean passed=playback && capture && builtinRoutes && notSilenced && detection.matched;
            result.put("state",passed?"compatible":"unknown");
            if(!passed) result.put("reason",!notSilenced?"recording_configuration_missing_or_silenced":!builtinRoutes?"requested_builtin_route_not_observed":!playback?"playback_head_incomplete":!capture?"capture_flow_incomplete":"known_pattern_not_detected_at_existing_volume");
        } catch(Throwable failure) {result.put("error_class",failure.getClass().getName());}
        finally {
            try {if(track!=null) {try {track.stop();} catch(Throwable ignored){} track.release();}}
            finally {try {if(record!=null) {try {record.stop();}catch(Throwable ignored){} record.release();}}
                finally {Arrays.fill(captured,(short)0);Arrays.fill(signal,(short)0);}}
        }
        return new JSONObject().put("status","observed").put("results",new JSONArray().put(result));
    }
}
