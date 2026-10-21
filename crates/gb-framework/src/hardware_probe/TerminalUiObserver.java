// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.terminaluiobserver;

import android.app.Instrumentation;
import android.app.UiAutomation;
import android.content.Context;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.os.UserManager;
import android.view.accessibility.AccessibilityManager;
import android.view.accessibility.AccessibilityNodeInfo;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONObject;

/** Self-targeted diagnostic instrumentation, never original-app instrumentation.
 * Public UI Automation temporarily establishes an accessibility connection while
 * preserving other accessibility services. Only scalar reductions leave this
 * process. No input, screenshot, settings, files or guest JavaScript operations.
 * Instrumentation.finish owns framework teardown; an external controller must
 * verify termination/cleanup and bind APK, boot, owner, focus and native lifetime.
 */
public final class TerminalUiObserver extends Instrumentation {
    static final String OWN="org.googlebook.port.terminaluiobserver";
    static final String TERMINAL="com.android.virtualization.terminal";
    static final String WEB="android.webkit.WebView";
    public static final String RESULT_KEY="gb_terminal_ui_observer";
    static final int MAX_NODES=4096, MAX_DEPTH=64, MAX_TEXT=4096,
        MAX_CHARS=262144, MAX_MATCHES=4096, MAX_SAMPLES=32, POLL_MS=250;

    // This is the sole status vocabulary; no exception messages/classes or app
    // supplied strings become status/error text.
    enum Trace {
        READY, COMPLETED, ARGUMENTS_REFUSED, OWNER_REFUSED, USER_LOCKED,
        ACCESSIBILITY_UNAVAILABLE, AUTOMATION_UNAVAILABLE, QUERY_FAILED,
        NO_ACTIVE_WINDOW, FOREIGN_ACTIVE_WINDOW, TERMINAL_NO_WEBVIEW,
        TERMINAL_WEBVIEW_EMPTY, TERMINAL_WEBVIEW_TEXT, NODE_LIMIT,
        DEPTH_LIMIT, TEXT_LIMIT, MATCH_LIMIT, POLL_DEADLINE,
        NODE_UNAVAILABLE, INTERRUPTED, DURATION_EXCEEDED,
        REPORT_FAILED, FINISH_FAILED;
        String value() { return name().toLowerCase(Locale.ROOT); }
    }
    static final class Observation {
        Trace status=Trace.NO_ACTIVE_WINDOW;
        int visited, webviews, foreign, nullChildren, textNodes, chars, whole, contains;
        boolean terminalWindow, complete, nodeLimit, depthLimit, textLimit,
            matchLimit, timeLimit, queryFailed, recycleFailed, accessibility, touch;
        long offset, elapsed;
        JSONObject json() throws Exception {
            return new JSONObject().put("status",status.value())
                .put("offset_ms",offset).put("query_elapsed_ms",elapsed)
                .put("terminal_window",terminalWindow).put("poll_complete",complete)
                .put("visited_nodes",visited).put("webview_roots",webviews)
                .put("foreign_subtrees_pruned",foreign).put("null_children",nullChildren)
                .put("nonempty_positive_width_text_nodes",textNodes)
                .put("text_characters_examined",chars)
                .put("whole_line_marker_matches",whole).put("contains_marker_matches",contains)
                .put("node_limit",nodeLimit).put("depth_limit",depthLimit)
                .put("text_limit",textLimit).put("match_limit",matchLimit)
                .put("poll_deadline_exceeded",timeLimit).put("query_failed",queryFailed)
                .put("node_recycle_failed",recycleFailed)
                .put("accessibility_enabled",accessibility).put("touch_exploration_enabled",touch);
        }
        boolean same(Observation r) {
            return r!=null && status==r.status && visited==r.visited && webviews==r.webviews
                && foreign==r.foreign && nullChildren==r.nullChildren && textNodes==r.textNodes
                && chars==r.chars && whole==r.whole && contains==r.contains
                && terminalWindow==r.terminalWindow && complete==r.complete
                && nodeLimit==r.nodeLimit && depthLimit==r.depthLimit && textLimit==r.textLimit
                && matchLimit==r.matchLimit && timeLimit==r.timeLimit && queryFailed==r.queryFailed
                && recycleFailed==r.recycleFailed && accessibility==r.accessibility && touch==r.touch;
        }
    }
    static final class Frame {
        final AccessibilityNodeInfo node;
        final int depth;
        final boolean belowWeb;
        boolean entered, childBelowWeb;
        int count, next;
        Frame(AccessibilityNodeInfo n,int d,boolean w) { node=n;depth=d;belowWeb=w; }
    }
    private int expectedUser, duration, heartbeatMs, heartbeatWindowMs;
    private String marker;
    private boolean validArgs;

    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        try {
            String user=args==null?null:args.getString("expected_user");
            String time=args==null?null:args.getString("duration_ms");
            marker=args==null?null:args.getString("marker");
            if(user==null || !user.matches("[0-9]{1,3}") || time==null
                    || !time.matches("[0-9]{4,5}") || marker==null
                    || !marker.matches("GB_UI_EXEC_[a-f0-9]{32}")) throw new IllegalArgumentException();
            expectedUser=Integer.parseInt(user); duration=Integer.parseInt(time);
            if(expectedUser>214 || duration<1000 || duration>90000) throw new IllegalArgumentException();
            String heartbeat=args.getString("readiness_heartbeat_ms");
            String window=args.getString("readiness_heartbeat_window_ms");
            if(heartbeat!=null || window!=null) {
                if(!"500".equals(heartbeat) || window==null
                        || !window.matches("[1-9][0-9]{2,3}")) throw new IllegalArgumentException();
                heartbeatMs=500;heartbeatWindowMs=Integer.parseInt(window);
                if(heartbeatWindowMs<500 || heartbeatWindowMs>8000
                        || heartbeatWindowMs>duration) throw new IllegalArgumentException();
            }
            validArgs=true;
        } catch(RuntimeException refused) { finishSafely(Trace.ARGUMENTS_REFUSED, new JSONObject()); return; }
        start();
    }
    static boolean heartbeatDue(int interval,int window,long offset,long lastReported) {
        return interval==500 && window>=500 && window<=8000 && lastReported>=0
            && offset>=lastReported && offset<=window && offset-lastReported>=interval;
    }
    private static boolean equal(CharSequence text,int start,int end,String expected) {
        if(end-start!=expected.length()) return false;
        for(int i=0;i<expected.length();i++) if(text.charAt(start+i)!=expected.charAt(i)) return false;
        return true;
    }
    static void text(Observation out,CharSequence value,String marker) {
        if(value==null || value.length()==0) return;
        out.textNodes++;
        int size=value.length();
        if(size>MAX_TEXT || size>MAX_CHARS-out.chars) {
            out.textLimit=true;out.status=Trace.TEXT_LIMIT;return;
        }
        out.chars+=size;
        for(int i=0;i+marker.length()<=size;i++) if(equal(value,i,i+marker.length(),marker)) {
            if(out.contains==MAX_MATCHES) { out.matchLimit=true;out.status=Trace.MATCH_LIMIT;return; }
            out.contains++; i+=marker.length()-1;
        }
        int start=0;
        for(int i=0;i<=size;i++) {
            if(i<size && value.charAt(i)!='\n' && value.charAt(i)!='\r') continue;
            if(equal(value,start,i,marker)) out.whole++;
            if(i<size && value.charAt(i)=='\r' && i+1<size && value.charAt(i+1)=='\n') i++;
            start=i+1;
        }
    }
    private static void recycle(Frame f,Observation out) {
        try { f.node.recycle(); } catch(RuntimeException failed) { out.recycleFailed=true; }
    }
    static Observation reduce(AccessibilityNodeInfo root,String marker,long deadline) {
        Observation out=new Observation();
        if(root==null) return out;
        ArrayDeque<Frame> stack=new ArrayDeque<>();
        stack.push(new Frame(root,0,false));
        try {
            while(!stack.isEmpty()) {
                if(SystemClock.elapsedRealtime()>=deadline) { out.timeLimit=true;out.status=Trace.POLL_DEADLINE;break; }
                Frame f=stack.peek();
                if(!f.entered) {
                    f.entered=true;out.visited++;
                    if(!TERMINAL.contentEquals(f.node.getPackageName()==null?"":f.node.getPackageName())) {
                        out.foreign++;stack.pop();recycle(f,out);continue;
                    }
                    if(f.depth==0) out.terminalWindow=true;
                    CharSequence name=f.node.getClassName();
                    boolean web=WEB.contentEquals(name==null?"":name);
                    if(web) out.webviews++;
                    f.childBelowWeb=f.belowWeb || web;
                    // Never request text on a native title, WebView root, foreign
                    // node or descendant reached through a foreign subtree.
                    if(f.belowWeb && !web) {
                        Rect bounds=new Rect();f.node.getBoundsInScreen(bounds);
                        if(bounds.width()>0) text(out,f.node.getText(),marker);
                        if(out.textLimit || out.matchLimit) break;
                    }
                    f.count=f.node.getChildCount();
                    if(f.count<0) { out.queryFailed=true;out.status=Trace.QUERY_FAILED;break; }
                    if(f.count>MAX_NODES-out.visited) { out.nodeLimit=true;out.status=Trace.NODE_LIMIT;break; }
                    if(f.depth==MAX_DEPTH && f.count>0) { out.depthLimit=true;out.status=Trace.DEPTH_LIMIT;break; }
                }
                if(f.next==f.count) { stack.pop();recycle(f,out);continue; }
                if(out.visited==MAX_NODES) { out.nodeLimit=true;out.status=Trace.NODE_LIMIT;break; }
                AccessibilityNodeInfo child=f.node.getChild(f.next++);
                if(child==null) { out.nullChildren++;continue; }
                stack.push(new Frame(child,f.depth+1,f.childBelowWeb));
            }
        } catch(RuntimeException unavailable) { out.queryFailed=true;out.status=Trace.QUERY_FAILED; }
        finally { while(!stack.isEmpty()) recycle(stack.pop(),out); }
        if(!out.terminalWindow && !out.timeLimit && !out.queryFailed) out.status=Trace.FOREIGN_ACTIVE_WINDOW;
        else if(!out.nodeLimit && !out.depthLimit && !out.textLimit && !out.matchLimit && !out.timeLimit && !out.queryFailed) {
            if(out.nullChildren>0 || out.recycleFailed) out.status=Trace.NODE_UNAVAILABLE;
            else {
                out.complete=true;
                out.status=out.webviews==0?Trace.TERMINAL_NO_WEBVIEW:
                    out.textNodes==0?Trace.TERMINAL_WEBVIEW_EMPTY:Trace.TERMINAL_WEBVIEW_TEXT;
            }
        }
        return out;
    }
    private static Bundle bundle(JSONObject value) {
        Bundle out=new Bundle();out.putString(RESULT_KEY,value.toString());return out;
    }
    private JSONObject common(Trace status,String kind) throws Exception {
        return new JSONObject().put("schema_version",1).put("probe","owned_terminal_ui_observer_v1")
            .put("status",status.value()).put("record_kind",kind).put("android_user",expectedUser)
            .put("uid",Process.myUid()).put("observation_only",true)
            .put("command_execution_verified",false).put("output_proof_claimed",false)
            .put("input_performed",false).put("raw_content_exported",false)
            .put("accessibility_cache_policy","clear_before_each_poll")
            .put("settings_or_permissions_changed",false).put("framework_cleanup_verified",false);
    }
    private void finishSafely(Trace status,JSONObject report) {
        try { report.put("status",status.value()).put("finish_requested",true).put("finish_failed",false)
                .put("framework_cleanup_verified",false); }
        catch(Exception failed) { status=Trace.REPORT_FAILED; }
        // Optional diagnostic serialization must never prevent this public
        // framework teardown attempt. No hidden UiAutomation disconnect API.
        Bundle result;
        try { result=bundle(report); } catch(RuntimeException failed) { result=new Bundle(); }
        try { finish(status==Trace.COMPLETED?0:2,result); }
        catch(RuntimeException failed) {
            try {
                JSONObject failure=new JSONObject().put("schema_version",1)
                    .put("status",Trace.FINISH_FAILED.value()).put("finish_requested",true)
                    .put("finish_failed",true).put("framework_cleanup_verified",false);
                sendStatus(2,bundle(failure));
            } catch(Exception ignored) { /* External controller must treat missing finish as unknown. */ }
        }
    }
    @Override public void onStart() {
        Trace status=Trace.COMPLETED;
        JSONObject report=new JSONObject();
        ArrayList<Observation> samples=new ArrayList<>();
        int polls=0, completePolls=0, dropped=0, maximumWhole=0, maximumContains=0;
        boolean readySent=false, acquired=false, managerAvailable=false;
        boolean beforeEnabled=false, beforeTouch=false, afterEnabled=false, afterTouch=false;
        boolean finalEnabled=false, finalTouch=false, interrupted=false;
        long started=SystemClock.elapsedRealtime(), maximumGap=0,lastPoll=-1,lastReported=-1;
        AccessibilityManager manager=null;
        Observation previous=null,last=null;
        try {
            if(!validArgs) { status=Trace.ARGUMENTS_REFUSED;return; }
            Context context=getTargetContext();
            int uid=Process.myUid();
            if(context==null || getContext()==null || !OWN.equals(context.getPackageName())
                    || !OWN.equals(getContext().getPackageName()) || uid/100000!=expectedUser
                    || uid%100000<10000 || uid%100000>=20000) { status=Trace.OWNER_REFUSED;return; }
            UserManager users=context.getSystemService(UserManager.class);
            if(users==null || !users.isUserUnlocked()) { status=Trace.USER_LOCKED;return; }
            manager=context.getSystemService(AccessibilityManager.class);
            if(manager==null) { status=Trace.ACCESSIBILITY_UNAVAILABLE;return; }
            managerAvailable=true;beforeEnabled=manager.isEnabled();beforeTouch=manager.isTouchExplorationEnabled();
            UiAutomation automation=getUiAutomation(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
            if(automation==null) { status=Trace.AUTOMATION_UNAVAILABLE;return; }
            acquired=true;afterEnabled=manager.isEnabled();afterTouch=manager.isTouchExplorationEnabled();
            JSONObject ready=common(Trace.READY,"ready")
                .put("accessibility_enabled_before_connection",beforeEnabled)
                .put("accessibility_enabled_after_connection",afterEnabled)
                .put("touch_exploration_before_connection",beforeTouch)
                .put("touch_exploration_after_connection",afterTouch)
                .put("ui_automation_acquired",true).put("first_poll_pending",true);
            sendStatus(1,bundle(ready));readySent=true;
            started=SystemClock.elapsedRealtime();
            long deadline=started+duration;
            while(SystemClock.elapsedRealtime()<deadline) {
                long begin=SystemClock.elapsedRealtime();
                if(lastPoll>=0) maximumGap=Math.max(maximumGap,begin-lastPoll);
                lastPoll=begin;
                Observation sample;
                try {
                    // Root/child accessibility queries normally reuse cached nodes.
                    // Clear only this connection's cache; this neither forces a
                    // DOM/render update nor proves an atomic current UI snapshot.
                    if(!automation.clearCache()) throw new IllegalStateException();
                    sample=reduce(automation.getRootInActiveWindow(),marker,Math.min(deadline,begin+POLL_MS));
                }
                catch(RuntimeException failed) { sample=new Observation();sample.queryFailed=true;sample.status=Trace.QUERY_FAILED; }
                sample.offset=begin-started;sample.elapsed=Math.max(0,SystemClock.elapsedRealtime()-begin);
                if(sample.elapsed>POLL_MS) { sample.timeLimit=true;sample.complete=false;sample.status=Trace.POLL_DEADLINE; }
                sample.accessibility=manager.isEnabled();sample.touch=manager.isTouchExplorationEnabled();
                polls++;if(sample.complete) completePolls++;
                maximumWhole=Math.max(maximumWhole,sample.whole);maximumContains=Math.max(maximumContains,sample.contains);
                last=sample;
                // Optional readiness heartbeats describe this actual, cache-cleared
                // poll. They neither synthesize observations nor guarantee cadence.
                // After the bounded window, retain the original change-only policy.
                if(!sample.same(previous)
                        || heartbeatDue(heartbeatMs,heartbeatWindowMs,sample.offset,lastReported)) {
                    if(samples.size()<MAX_SAMPLES) {
                        samples.add(sample);
                        sendStatus(1,bundle(common(sample.status,"sample").put("sample",sample.json())));
                    } else { dropped++;samples.set(MAX_SAMPLES-1,sample); }
                    previous=sample;
                    lastReported=sample.offset;
                }
                long wait=Math.min(deadline-SystemClock.elapsedRealtime(),POLL_MS-(SystemClock.elapsedRealtime()-begin));
                if(wait>0) Thread.sleep(wait);
            }
            if(last!=null && (samples.isEmpty() || samples.get(samples.size()-1)!=last)) {
                if(samples.size()<MAX_SAMPLES) samples.add(last);
                else { dropped++;samples.set(MAX_SAMPLES-1,last); }
            }
            if(SystemClock.elapsedRealtime()-started>duration+1000L) status=Trace.DURATION_EXCEEDED;
        } catch(InterruptedException stopped) { interrupted=true;status=Trace.INTERRUPTED; }
        catch(RuntimeException failed) { status=Trace.QUERY_FAILED; }
        catch(Exception failed) { status=Trace.REPORT_FAILED; }
        finally {
            try {
                if(manager!=null) { finalEnabled=manager.isEnabled();finalTouch=manager.isTouchExplorationEnabled(); }
                JSONArray rows=new JSONArray();for(Observation sample:samples) rows.put(sample.json());
                report=common(status,"final").put("requested_duration_ms",duration)
                    .put("observation_elapsed_ms",Math.max(0,SystemClock.elapsedRealtime()-started))
                    .put("poll_interval_ms",POLL_MS).put("polls",polls).put("complete_polls",completePolls)
                    .put("maximum_poll_start_gap_ms",maximumGap).put("samples",rows)
                    .put("sample_budget",MAX_SAMPLES).put("samples_dropped",dropped)
                    .put("sample_budget_exceeded",dropped>0).put("ready_sent",readySent)
                    .put("ui_automation_acquired",acquired).put("accessibility_manager_available",managerAvailable)
                    .put("accessibility_enabled_before_connection",beforeEnabled)
                    .put("accessibility_enabled_after_connection",afterEnabled)
                    .put("accessibility_enabled_before_finish",finalEnabled)
                    .put("touch_exploration_before_connection",beforeTouch)
                    .put("touch_exploration_after_connection",afterTouch)
                    .put("touch_exploration_before_finish",finalTouch)
                    .put("maximum_whole_line_marker_matches",maximumWhole)
                    .put("maximum_contains_marker_matches",maximumContains)
                    .put("node_budget_per_poll",MAX_NODES).put("depth_budget",MAX_DEPTH)
                    .put("text_characters_per_node_budget",MAX_TEXT).put("text_characters_per_poll_budget",MAX_CHARS)
                    .put("marker_match_budget_per_poll",MAX_MATCHES);
                if(report.toString().length()>65536) { status=Trace.REPORT_FAILED;report=new JSONObject(); }
            } catch(Exception failed) { status=Trace.REPORT_FAILED;report=new JSONObject(); }
            finally { finishSafely(status,report);if(interrupted) Thread.currentThread().interrupt(); }
        }
    }
}
