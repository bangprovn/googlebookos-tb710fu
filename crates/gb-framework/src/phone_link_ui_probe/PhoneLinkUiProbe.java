// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.phonelinkui;

import android.app.Instrumentation;
import android.app.UiAutomation;
import android.content.Context;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.os.UserManager;
import android.view.accessibility.AccessibilityNodeInfo;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONObject;

/** Self-targeted, no-permission observation. No input/events, settings, screenshots,
 * WebView/foreign traversal, network or files. Public synchronous queries have a
 * cooperative deadline; the caller MUST also bound instrumentation externally.
 * finish() requests framework disconnect; it does not verify external teardown.
 */
public final class PhoneLinkUiProbe extends Instrumentation {
    static final String OWN="org.googlebook.port.phonelinkui";
    static final String TARGET="com.google.ambient.streaming";
    static final String RESULT="gb_phone_link_ui_probe";
    static final String APK="518884a1bf141dd2f83308b5833a729c36f4db59456d19554e9f0ab43008e82f";
    static final String WHITELIST="49a64b6d977e51e64c97c7b1232fbc9be80c8ef9ac6750e15f18b8a9a8ef4061";
    static final int MAX_NODES=512,MAX_DEPTH=32,MAX_TEXT=2048,MAX_CHARS=65536,POLL_MS=250;
    static final String[] KEYS={"searching_label","setup_intro_title","setup_intro_body",
        "setup_required_title","setup_required_body","setup_new_phone_option",
        "wifi_required_body","phone_app_cast_disabled_body","open_settings_on_phone",
        "wifi_disconnected_description","onboarding_illustration_description"};
    static final String[] LITERALS={"Searching for nearby devices","Cast your phone’s apps",
        "Use your Android phone’s apps on your Googlebook with no installs needed",
        "Check your phone to continue setup","Follow the guided setup on your phone to allow permissions",
        "Set up new phone","You need to turn on Wi-Fi",
        "Turn on App Cast in Cross-device services on your Phone to access apps from your phone on this device.",
        "Open Settings on phone","Wi-Fi disconnected","Onboarding illustration"};
    enum Status { COMPLETED, ARGUMENTS_REFUSED, OWNER_REFUSED, USER_LOCKED,
        AUTOMATION_UNAVAILABLE, QUERY_INCOMPLETE, INTERRUPTED, DURATION_EXCEEDED;
        String value(){return name().toLowerCase(Locale.ROOT);} }
    enum Query { NATIVE_OBSERVED, NO_ACTIVE_WINDOW, FOREIGN_ACTIVE_WINDOW, WEBVIEW_ACTIVE_WINDOW,
        QUERY_FAILED, NODE_LIMIT, DEPTH_LIMIT, TEXT_LIMIT, POLL_DEADLINE, NODE_UNAVAILABLE;
        String value(){return name().toLowerCase(Locale.ROOT);} }
    static final class Sample {
        Query status=Query.NO_ACTIVE_WINDOW;
        long offset,elapsed;
        int visited,foreign,webviews,nullChildren,recycled,chars;
        boolean target,complete,nodeLimit,depthLimit,textLimit,timeLimit,queryFailed,recycleFailed;
        int[] text=new int[11],description=new int[11];
        JSONObject json() throws Exception {
            JSONObject a=new JSONObject(),b=new JSONObject();
            for(int i=0;i<11;i++){a.put(KEYS[i],text[i]);b.put(KEYS[i],description[i]);}
            return new JSONObject().put("status",status.value()).put("offset_ms",offset)
                .put("query_elapsed_ms",elapsed).put("target_window",target).put("poll_complete",complete)
                .put("visited_nodes",visited).put("foreign_subtrees_pruned",foreign)
                .put("webview_subtrees_pruned",webviews).put("null_children",nullChildren)
                .put("nodes_recycled",recycled).put("text_characters_examined",chars)
                .put("node_limit",nodeLimit).put("depth_limit",depthLimit).put("text_limit",textLimit)
                .put("poll_deadline_exceeded",timeLimit).put("query_failed",queryFailed)
                .put("node_recycle_failed",recycleFailed).put("text_counts",a).put("description_counts",b);
        }
    }
    static final class Frame {
        final AccessibilityNodeInfo node; final int depth;
        boolean entered;int next,count;
        Frame(AccessibilityNodeInfo n,int d){node=n;depth=d;}
    }
    private boolean valid;
    private int cacheAttempts,cacheSuccesses,rootQueries;
    @Override public void onCreate(Bundle args){
        super.onCreate(args);
        if(args==null || !"11".equals(args.getString("expected_user"))){finishReport(Status.ARGUMENTS_REFUSED,new ArrayList<Sample>(),0,false);return;}
        valid=true;start();
    }
    static void count(Sample s,CharSequence value,int[] counts){
        if(value==null || value.length()==0)return;
        int length=value.length();
        if(length>MAX_TEXT || length>MAX_CHARS-s.chars){s.textLimit=true;s.status=Query.TEXT_LIMIT;return;}
        s.chars+=length;
        for(int i=0;i<11;i++)if(LITERALS[i].contentEquals(value)){counts[i]++;return;}
    }
    static void recycle(Frame f,Sample s){
        try{f.node.recycle();s.recycled++;}catch(RuntimeException failed){s.recycleFailed=true;}
    }
    static Sample reduce(AccessibilityNodeInfo root,long deadline){
        Sample s=new Sample();if(root==null)return s;
        ArrayDeque<Frame> stack=new ArrayDeque<>();stack.push(new Frame(root,0));
        try{
            while(!stack.isEmpty()){
                if(SystemClock.elapsedRealtime()>=deadline){s.timeLimit=true;s.status=Query.POLL_DEADLINE;break;}
                Frame f=stack.peek();
                if(!f.entered){
                    f.entered=true;s.visited++;
                    if(!TARGET.contentEquals(f.node.getPackageName()==null?"":f.node.getPackageName())){
                        s.foreign++;stack.pop();recycle(f,s);continue;
                    }
                    if(f.depth==0)s.target=true;
                    if("android.webkit.WebView".contentEquals(f.node.getClassName()==null?"":f.node.getClassName())){
                        s.webviews++;stack.pop();recycle(f,s);continue;
                    }
                    Rect bounds=new Rect();f.node.getBoundsInScreen(bounds);
                    if(bounds.width()>0 && bounds.height()>0 && f.node.isVisibleToUser()){
                        count(s,f.node.getText(),s.text);if(s.textLimit)break;
                        count(s,f.node.getContentDescription(),s.description);if(s.textLimit)break;
                    }
                    f.count=f.node.getChildCount();
                    if(f.count<0){s.queryFailed=true;s.status=Query.QUERY_FAILED;break;}
                    if(f.count>MAX_NODES-s.visited){s.nodeLimit=true;s.status=Query.NODE_LIMIT;break;}
                    if(f.depth==MAX_DEPTH && f.count>0){s.depthLimit=true;s.status=Query.DEPTH_LIMIT;break;}
                }
                if(f.next==f.count){stack.pop();recycle(f,s);continue;}
                if(s.visited==MAX_NODES){s.nodeLimit=true;s.status=Query.NODE_LIMIT;break;}
                AccessibilityNodeInfo child=f.node.getChild(f.next++);
                if(child==null){s.nullChildren++;continue;}
                stack.push(new Frame(child,f.depth+1));
            }
        }catch(RuntimeException failed){s.queryFailed=true;s.status=Query.QUERY_FAILED;}
        finally{while(!stack.isEmpty())recycle(stack.pop(),s);}
        if(!s.target && !s.timeLimit && !s.queryFailed)s.status=Query.FOREIGN_ACTIVE_WINDOW;
        else if(s.target && s.visited==1 && s.webviews==1 && !s.timeLimit && !s.queryFailed)s.status=Query.WEBVIEW_ACTIVE_WINDOW;
        else if(!s.nodeLimit&&!s.depthLimit&&!s.textLimit&&!s.timeLimit&&!s.queryFailed){
            if(s.nullChildren>0||s.recycleFailed)s.status=Query.NODE_UNAVAILABLE;
            else{s.complete=true;s.status=Query.NATIVE_OBSERVED;}
        }
        return s;
    }
    private void finishReport(Status status,ArrayList<Sample> samples,long elapsed,boolean acquired){
        Bundle result=new Bundle();
        try{
            JSONArray rows=new JSONArray();for(Sample s:samples)rows.put(s.json());
            JSONObject r=new JSONObject().put("schema_version",1).put("probe","owned_phone_link_ui_v1")
                .put("status",status.value()).put("android_user",11).put("uid",Process.myUid())
                .put("expected_target_uid",1110128).put("target_package",TARGET)
                .put("expected_target_apk_sha256",APK).put("whitelist_sha256",WHITELIST)
                .put("observation_only",true).put("input_performed",false).put("raw_content_exported",false)
                .put("settings_or_permissions_changed",false).put("framework_cleanup_verified",false)
                .put("registration_verified",false).put("active_rf_scan_verified",false)
                .put("peer_eligibility_verified",false).put("functional_phone_link_verified",false)
                .put("external_target_identity_verified",false).put("ui_automation_acquired",acquired)
                .put("accessibility_cache_policy","clear_before_each_poll")
                .put("cache_clear_attempts",cacheAttempts).put("cache_clear_successes",cacheSuccesses)
                .put("root_queries",rootQueries)
                .put("observation_elapsed_ms",elapsed).put("node_budget_per_poll",MAX_NODES)
                .put("depth_budget",MAX_DEPTH).put("text_characters_per_field_budget",MAX_TEXT)
                .put("text_characters_per_poll_budget",MAX_CHARS).put("window_budget_per_poll",1)
                .put("sample_budget",2).put("samples",rows).put("finish_requested",true).put("finish_failed",false);
            result.putString(RESULT,r.toString());
        }catch(Exception failed){/* Missing report stays unknown; never skip public teardown. */}
        try{finish(status==Status.COMPLETED?0:2,result);}catch(RuntimeException failed){/* Caller must treat missing completion as unknown. */}
    }
    @Override public void onStart(){
        Status status=Status.QUERY_INCOMPLETE;ArrayList<Sample> samples=new ArrayList<>();
        boolean acquired=false;long started=SystemClock.elapsedRealtime();
        try{
            if(!valid){status=Status.ARGUMENTS_REFUSED;return;}
            Context c=getTargetContext();int uid=Process.myUid();
            if(c==null||getContext()==null||!OWN.equals(c.getPackageName())||!OWN.equals(getContext().getPackageName())
                    ||uid/100000!=11||uid%100000<10000||uid%100000>=20000){status=Status.OWNER_REFUSED;return;}
            UserManager u=c.getSystemService(UserManager.class);
            if(u==null||!u.isUserUnlocked()){status=Status.USER_LOCKED;return;}
            UiAutomation a=getUiAutomation(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
            if(a==null){status=Status.AUTOMATION_UNAVAILABLE;return;}
            acquired=true;started=SystemClock.elapsedRealtime();long deadline=started+8000;
            for(int i=0;i<2;i++){
                while(i==1){
                    long remaining=5500-(SystemClock.elapsedRealtime()-started);
                    if(remaining<=0)break;
                    if(Thread.currentThread().isInterrupted())throw new InterruptedException();
                    Thread.sleep(Math.min(50,remaining));
                }
                long begin=SystemClock.elapsedRealtime();if(begin>=deadline){status=Status.DURATION_EXCEEDED;break;}
                Sample s;
                try{cacheAttempts++;if(!a.clearCache())throw new IllegalStateException();cacheSuccesses++;rootQueries++;s=reduce(a.getRootInActiveWindow(),Math.min(deadline,begin+POLL_MS));}
                catch(RuntimeException failed){s=new Sample();s.queryFailed=true;s.status=Query.QUERY_FAILED;}
                s.offset=begin-started;s.elapsed=Math.max(0,SystemClock.elapsedRealtime()-begin);
                if(s.elapsed>POLL_MS){s.timeLimit=true;s.complete=false;s.status=Query.POLL_DEADLINE;}
                samples.add(s);
            }
            if(SystemClock.elapsedRealtime()>=deadline)status=Status.DURATION_EXCEEDED;
            else if(samples.size()==2&&samples.get(0).complete&&samples.get(1).complete)status=Status.COMPLETED;
        }catch(InterruptedException interrupted){Thread.currentThread().interrupt();status=Status.INTERRUPTED;}
        catch(RuntimeException failed){status=Status.QUERY_INCOMPLETE;}
        finally{finishReport(status,samples,Math.max(0,SystemClock.elapsedRealtime()-started),acquired);}
    }
}
