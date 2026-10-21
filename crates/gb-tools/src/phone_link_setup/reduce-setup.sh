#!/system/bin/sh
# One bounded private UIAutomator XML file -> native fixed-label geometry only.
# Run on device; never export the input. No input/events/settings/network/files.
set -eu
[ "$#" -eq 1 ] || exit 2
[ -f "$1" ] && [ ! -L "$1" ] || exit 2
bytes=$(wc -c < "$1")
[ "$bytes" -gt 0 ] && [ "$bytes" -le 65536 ] || exit 2
awk '
function refuse() { bad=1; print "Phone Link UI redaction refused" > "/dev/stderr"; exit 2 }
function emit(s) { output_chars+=length(s)+1; if(output_chars>60000)refuse(); print s }
function literal(s) {
    return s=="Searching for nearby devices" || s=="Cast your phone’s apps" ||
      s=="Use your Android phone’s apps on your Googlebook with no installs needed" ||
      s=="Check your phone to continue setup" ||
      s=="Follow the guided setup on your phone to allow permissions" ||
      s=="Set up new phone" || s=="You need to turn on Wi-Fi" ||
      s=="Turn on App Cast in Cross-device services on your Phone to access apps from your phone on this device." ||
      s=="Open Settings on phone" || s=="Wi-Fi disconnected" || s=="Onboarding illustration" ||
      s=="Get started" || s=="Scan the QR code using your phone to start setup";
}
BEGIN {
    RS="<";q=sprintf("%c",39);
    pat="^[[:space:]]*[A-Za-z_][A-Za-z0-9_.:-]*=(\"[^\"]*\"|" q "[^" q "]*" q ")";
    emit("<gb-phone-link-ui><hierarchy>");
}
NR==1 { if($0 !~ /^[[:space:]]*$/) refuse(); next }
{
    tag=$0;sub(/[[:space:]]*$/,"",tag);
    if(length(tag)>65536 || substr(tag,length(tag),1)!=">")refuse();
    tag=substr(tag,1,length(tag)-1);
    if(tag ~ /^\?xml[[:space:]]/ && !started && nodes==0)next;
    if(tag ~ /^hierarchy([[:space:]]|$)/ && !started){started=1;next;}
    if(tag=="/hierarchy" && started && !finished && depth==0){finished=1;next;}
    if(!started || finished)refuse();
    if(tag=="/node"){if(depth<=0)refuse();delete native[depth];depth--;emit("</node>");next;}
    if(tag !~ /^node([[:space:]]|$)/)refuse();
    nodes++;if(nodes>512 || depth+1>32)refuse();
    rest=substr(tag,5);selfclose=(rest ~ /\/[[:space:]]*$/);
    if(selfclose)sub(/\/[[:space:]]*$/,"",rest);
    for(k in attrs)delete attrs[k];
    while(rest !~ /^[[:space:]]*$/){
        if(!match(rest,pat))refuse();
        a=substr(rest,1,RLENGTH);rest=substr(rest,RLENGTH+1);sub(/^[[:space:]]*/,"",a);
        eq=index(a,"=");k=substr(a,1,eq-1);v=substr(a,eq+2,length(a)-eq-2);
        if(k in attrs)refuse();attrs[k]=v;
    }
    scope=(attrs["package"]=="com.google.ambient.streaming"?"own":"foreign");
    cls=attrs["class"];
    if(cls!="android.view.View" && cls!="android.widget.TextView" && cls!="android.widget.Button" &&
       cls!="android.widget.ImageButton" && cls!="android.widget.ImageView" && cls!="android.webkit.WebView" &&
       cls!="android.widget.FrameLayout" && cls!="android.widget.LinearLayout" && cls!="android.widget.RelativeLayout" && cls!="android.widget.ScrollView")cls="redacted.Other";
    if(attrs["bounds"] !~ /^\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]$/ || length(attrs["bounds"])>64)refuse();
    if((attrs["enabled"]!="true" && attrs["enabled"]!="false") ||
       (attrs["clickable"]!="true" && attrs["clickable"]!="false"))refuse();
    visibility="unknown";
    if("visible-to-user" in attrs){visibility=attrs["visible-to-user"];visibility_fields++;}
    if("visible" in attrs){if(visibility!="unknown" && visibility!=attrs["visible"])refuse();visibility=attrs["visible"];visibility_fields++;}
    if(visibility!="unknown" && visibility!="true" && visibility!="false")refuse();
    safe=(scope=="own" && cls!="android.webkit.WebView" && cls!="redacted.Other" && (depth==0 || native[depth]));
    text="";description="";
    # Unknown values are never compared or emitted on a foreign/WebView path.
    if(safe){if(literal(attrs["text"]))text=attrs["text"];if(literal(attrs["content-desc"]))description=attrs["content-desc"];}
    out=" package_scope=\"" scope "\" class=\"" cls "\" bounds=\"" attrs["bounds"] "\" enabled=\"" attrs["enabled"] "\" clickable=\"" attrs["clickable"] "\" visibility=\"" visibility "\" text=\"" text "\" content-desc=\"" description "\"";
    if(selfclose)emit("<node" out "/>");
    else{depth++;if(depth>32)refuse();native[depth]=safe;emit("<node" out ">");}
}
END {
    if(bad)exit 2;
    if(!started || !finished || depth!=0 || nodes==0){print "Phone Link UI redaction incomplete" > "/dev/stderr";exit 2;}
    emit("</hierarchy><gb-meta complete=\"true\" node_count=\"" nodes "\" visibility_attributes=\"" (visibility_fields+0) "\" raw_content_exported=\"false\"/></gb-phone-link-ui>");
}
' "$1"
