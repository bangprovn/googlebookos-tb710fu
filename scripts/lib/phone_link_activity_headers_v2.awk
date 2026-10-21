# Full reference-format Phone Link activity header scalar reduction, ON DEVICE.
# Exactly one target header: running7tokens or not-running8tokens. No NF5 or
# unknown-extra fallback. Fixed owner11 AND uid1110128; bounded PID/display.
# This verifies only text-format/scope, never process identity or foreground.
# Append GB_PHONE_LINK_ACTIVITY_END_V2 <32hex nonce> <producer exit> after query.
function integer(s,hi) { return s ~ /^(0|[1-9][0-9]*)$/ && length(s)<=10 && s+0<=hi }
function display(token, s,n,a) {
    if(index(token,"displayId=")!=1)return 0
    s=substr(token,11)
    if(s=="N/A")return 1
    n=split(s,a,"\\(type=")
    return n==2 && integer(a[1],2147483647) && a[2] ~ /^(INTERNAL|EXTERNAL|VIRTUAL|OVERLAY|WIFI|UNKNOWN)\)$/
}
BEGIN {
    short="com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity"
    full="com.google.ambient.streaming/com.google.ambient.streaming.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity"
    trailer="GB_PHONE_LINK_ACTIVITY_END_V2 "frame_nonce" ";producer=-1
    if(length(frame_nonce)!=32 || frame_nonce !~ /^[0-9a-f]+$/) { bad=1;exit 2 }
}
{
    lines++;bytes+=length($0)+1
    if(lines>8192 || bytes>1048576 || length($0)>4096 || index($0,"\r")) { bad=1;exit 2 }
    last=$0
    if(index($0,"GB_PHONE_LINK_ACTIVITY_END_V2 ")==1) {
        if(complete || index($0,trailer)!=1) { bad=1;next }
        code=substr($0,length(trailer)+1)
        if(code !~ /^(0|[1-9][0-9]?[0-9]?)$/ || code+0>255) { bad=1;next }
        complete++;producer=code+0;next
    }
    if(complete) { bad=1;next }
    if($1!="ACTIVITY" || ($2!=short && $2!=full))next
    headers++
    if(headers>4) { bad=1;exit 2 }
    if($3 !~ /^[0-9a-fA-F]+$/ || length($3)>16) { malformed++;next }
    is_running=0
    if(NF==7 && index($4,"pid=")==1 && integer(substr($4,5),4194304) && substr($4,5)+0>0) {
        user=$5;uid=$6;shown=$7;is_running=1
    } else if(NF==8 && $4=="pid=(not" && $5=="running)") {
        user=$6;uid=$7;shown=$8
    } else { malformed++;next }
    if(index(user,"userId=")!=1 || !integer(substr(user,8),214) ||
             index(uid,"uid=")!=1 || !integer(substr(uid,5),2147483647) ||
             !display(shown)) { malformed++;next }
    if(user!="userId=11" || uid!="uid=1110128") { scope_refused++;next }
    if(is_running)running++;else not_running++
}
END {
    framed=(!bad && complete==1 && index(last,trailer)==1);dump_complete=(framed && producer==0)
    verified=(dump_complete && headers==1 && malformed==0 && scope_refused==0 && running+not_running==1)
    status=!framed?"framing_refused":producer!=0?"producer_failed":headers==0?"no_matching_header":headers!=1?"header_count_refused":malformed?"header_format_unknown":scope_refused?"header_scope_refused":"header_format_observed"
    printf "{\"schema_version\":2,\"status\":\"%s\",\"dump_complete\":%s,\"producer_exit_code\":",status,(dump_complete?"true":"false")
    if(framed)printf "%d",producer;else printf "null"
    printf ",\"matching_headers\":%d,\"owner_running_headers\":%d,\"owner_not_running_headers\":%d,\"malformed_target_headers\":%d,\"scope_refused_headers\":%d,\"header_format_verified\":%s,\"identity_verified\":false,\"foreground_verified\":false,\"raw_fields_exported\":false}\n",(dump_complete?headers:0),(verified?running:0),(verified?not_running:0),(dump_complete?malformed:0),(dump_complete?scope_refused:0),(verified?"true":"false")
    if(!dump_complete || malformed || scope_refused || headers>1)exit 2
}
