// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONArray;
import org.json.JSONObject;

/** Passive public network APIs and one fixed HTTPS request; no radio/settings controls.
 * Fixed endpoint: AOSP NetworkStackUtils.java at 20fcc7622e151794c8d6b0bd0e2b81ab24c8d2d0.
 * Never stringify Network/NetworkCapabilities/LinkProperties or export addresses/content.
 */
final class NetworkProbe {
    private static final String ENDPOINT="https://www.google.com/generate_204";
    private static JSONObject row(String operation) throws Exception {
        return new JSONObject().put("operation",operation).put("state","unknown");
    }
    private static final class Callbacks extends ConnectivityManager.NetworkCallback {
        final Network selected;
        int observations,available,capabilities,lost;
        boolean matchingAvailable,matchingCapabilities,changed,overBudget;
        Callbacks(Network selected) { this.selected=selected; }
        private boolean accept() {
            if(observations>=32) { overBudget=true; return false; }
            observations++; return true;
        }
        @Override public synchronized void onAvailable(Network network) {
            if(!accept()) return;
            available++; if(selected.equals(network)) matchingAvailable=true; else changed=true;
        }
        @Override public synchronized void onCapabilitiesChanged(Network network,NetworkCapabilities value) {
            if(!accept()) return;
            capabilities++; if(selected.equals(network) && value!=null) matchingCapabilities=true; else changed=true;
        }
        @Override public synchronized void onLost(Network network) {
            if(!accept()) return;
            lost++; if(selected.equals(network)) changed=true;
        }
        synchronized void report(JSONObject result) throws Exception {
            result.put("observations",observations).put("available_events",available)
                .put("capability_events",capabilities).put("lost_events",lost)
                .put("matching_available",matchingAvailable).put("matching_capabilities",matchingCapabilities)
                .put("network_change_observed",changed).put("observation_budget_exceeded",overBudget);
        }
    }
    private static final class HttpsResult {
        boolean attempted,defaultTls,emptyBody,streamClosed,disconnectCalled;
        int code=-1,bodyBytesRead=-1;
        String outcome="no_eligible_default_network";
    }
    private static HttpsResult https(Network network,AtomicBoolean attempted) {
        HttpsResult result=new HttpsResult();
        HttpsURLConnection connection=null;
        try {
            // This is a fresh owned app process. Refuse a cookie handler and install
            // an app-private denying authenticator; never invoke account/credential APIs.
            if(CookieHandler.getDefault()!=null) {
                result.outcome="unexpected_auth_or_cookie_handler"; return result;
            }
            Authenticator.setDefault(new Authenticator() {
                @Override protected PasswordAuthentication getPasswordAuthentication() { return null; }
            });
            if(Thread.currentThread().isInterrupted()) { result.outcome="observer_deadline"; return result; }
            result.attempted=true; attempted.set(true);
            URLConnection opened=network.openConnection(new URL(ENDPOINT));
            if(!(opened instanceof HttpsURLConnection)) { result.outcome="unexpected_connection_type"; return result; }
            connection=(HttpsURLConnection)opened;
            connection.setConnectTimeout(4000); connection.setReadTimeout(4000);
            connection.setInstanceFollowRedirects(false); connection.setUseCaches(false);
            connection.setAllowUserInteraction(false); connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent","Googlebook-Port-NetworkProbe/1");
            connection.setRequestProperty("Connection","close");
            // No custom socket factory, hostname verifier or certificate trust.
            // The app-private authenticator above rejects credentials.
            result.defaultTls=connection.getSSLSocketFactory()==HttpsURLConnection.getDefaultSSLSocketFactory()
                && connection.getHostnameVerifier()==HttpsURLConnection.getDefaultHostnameVerifier();
            if(!result.defaultTls) { result.outcome="unexpected_tls_defaults"; return result; }
            result.code=connection.getResponseCode();
            if(result.code!=204) { result.outcome="unexpected_http_status"; return result; }
            if(!connection.getURL().toExternalForm().equals(ENDPOINT)) { result.outcome="endpoint_changed"; return result; }
            result.streamClosed=false;
            try(InputStream stream=connection.getInputStream()) {
                int first=stream.read(); // At most one byte; never retain/export its value.
                result.bodyBytesRead=first<0?0:1; result.emptyBody=first<0;
            }
            result.streamClosed=true;
            result.outcome=result.emptyBody?"https_204_empty_body":"unexpected_body";
        } catch(javax.net.ssl.SSLException unavailable) { result.outcome="tls_error"; }
        catch(Exception unavailable) { result.outcome="request_error"; }
        finally {
            if(connection!=null) { connection.disconnect(); result.disconnectCalled=true; }
        }
        return result;
    }
    static JSONObject run(Context context) throws Exception {
        ConnectivityManager manager=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network selected=manager==null?null:manager.getActiveNetwork();
        NetworkCapabilities caps=selected==null?null:manager.getNetworkCapabilities(selected);
        JSONObject snapshot=row("default_network_snapshot").put("default_present",selected!=null)
            .put("capabilities_available",caps!=null).put("internet",false).put("validated",false)
            .put("transport_wifi",false).put("transport_cellular",false)
            .put("transport_ethernet",false).put("transport_vpn",false);
        if(caps!=null) snapshot.put("state","compatible")
            .put("internet",caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
            .put("validated",caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
            .put("transport_wifi",caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
            .put("transport_cellular",caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
            .put("transport_ethernet",caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
            .put("transport_vpn",caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
        JSONObject callbacks=row("default_network_callbacks").put("registered",false).put("removed",false)
            .put("thread_stopped",true).put("window_ms",0).put("observations",0)
            .put("available_events",0).put("capability_events",0).put("lost_events",0)
            .put("matching_available",false).put("matching_capabilities",false)
            .put("network_change_observed",false).put("observation_budget_exceeded",false);
        boolean matchesAtChecks=selected!=null && selected.equals(manager.getActiveNetwork());
        if(selected!=null) {
            HandlerThread thread=new HandlerThread("gb-owned-network-callbacks"); thread.start();
            Callbacks listener=new Callbacks(selected);
            boolean registered=false,removed=false;
            long start=SystemClock.elapsedRealtime();
            try {
                manager.registerDefaultNetworkCallback(listener,new Handler(thread.getLooper())); registered=true;
                Thread.sleep(2000);
            } catch(RuntimeException unavailable) { /* Aggregate unknown; no exception messages. */ }
            finally {
                try { if(registered) { manager.unregisterNetworkCallback(listener); removed=true; } }
                finally { thread.quit(); thread.join(1000); }
            }
            long elapsed=SystemClock.elapsedRealtime()-start;
            matchesAtChecks &= selected.equals(manager.getActiveNetwork());
            callbacks.put("registered",registered).put("removed",removed).put("thread_stopped",!thread.isAlive()).put("window_ms",elapsed);
            listener.report(callbacks);
            boolean ok=registered && removed && !thread.isAlive() && matchesAtChecks && elapsed>=2000 && elapsed<=10000
                && callbacks.getBoolean("matching_available") && callbacks.getBoolean("matching_capabilities")
                && !callbacks.getBoolean("network_change_observed") && !callbacks.getBoolean("observation_budget_exceeded");
            callbacks.put("state",ok?"compatible":"unknown");
        }
        HttpsResult response=new HttpsResult();
        boolean stopped=true,timedOut=false;
        final AtomicBoolean attempted=new AtomicBoolean();
        if(selected!=null && caps!=null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && matchesAtChecks) {
            final Network captured=selected;
            ExecutorService executor=Executors.newSingleThreadExecutor(new ThreadFactory() {
                @Override public Thread newThread(Runnable runnable) {
                    Thread thread=new Thread(runnable,"gb-owned-fixed-https"); thread.setDaemon(true); return thread;
                }
            });
            Future<HttpsResult> future=null;
            try {
                future=executor.submit(new Callable<HttpsResult>() { @Override public HttpsResult call() { return https(captured,attempted); } });
                response=future.get(12,TimeUnit.SECONDS);
            } catch(java.util.concurrent.TimeoutException unavailable) { timedOut=true; response.outcome="observer_deadline"; }
            catch(java.util.concurrent.ExecutionException unavailable) { response.outcome="worker_error"; }
            finally {
                if(future!=null) future.cancel(true);
                executor.shutdownNow(); stopped=executor.awaitTermination(1000,TimeUnit.MILLISECONDS);
            }
        }
        response.attempted |= attempted.get();
        boolean after=selected!=null && selected.equals(manager.getActiveNetwork());
        boolean success=response.code==204 && response.defaultTls && response.emptyBody && response.bodyBytesRead==0
            && response.streamClosed && response.disconnectCalled && stopped && !timedOut && matchesAtChecks && after;
        JSONObject https=row("fixed_https_204").put("state",success?"compatible":"unknown")
            .put("endpoint",ENDPOINT).put("request_count_limit",1).put("attempted",response.attempted)
            .put("outcome",response.outcome).put("response_code",response.code).put("body_bytes_read",response.bodyBytesRead<0?JSONObject.NULL:response.bodyBytesRead)
            .put("empty_body",response.emptyBody).put("response_stream_closed",response.streamClosed)
            .put("disconnect_called",response.disconnectCalled).put("worker_stopped",stopped).put("observer_timed_out",timedOut)
            .put("default_tls_verification_used",response.defaultTls).put("redirects_enabled",false)
            .put("credentials_or_cookies_sent",false).put("body_content_exported",false)
            .put("captured_network_used",response.attempted).put("default_network_matches_at_checks",matchesAtChecks && after)
            .put("connect_timeout_ms",4000).put("read_timeout_ms",4000).put("observer_timeout_ms",12000);
        return new JSONObject().put("status","observed").put("settings_changed",false)
            .put("network_requested_or_process_bound",false).put("network_identifiers_collected",false)
            .put("content_collected",false).put("wifi_reconnect_verified",false).put("radio_change_performed",false)
            .put("results",new JSONArray().put(snapshot).put(callbacks).put(https));
    }
}
