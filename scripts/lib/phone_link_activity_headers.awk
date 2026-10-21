# Bounded on-device header counts only. Do not save/forward dumpsys input.
# Exact short/full framework component spellings; never activity/private UI text.
# Append GB_PHONE_LINK_ACTIVITY_END_V1 <nonce> <producer-exit> unconditionally.
BEGIN {
    short="com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity"
    full="com.google.ambient.streaming/com.google.ambient.streaming.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity"
    trailer="GB_PHONE_LINK_ACTIVITY_END_V1 "frame_nonce" ";producer=-1
    if(length(frame_nonce)!=32 || frame_nonce !~ /^[0-9a-f]+$/) { bad=1;exit 2 }
}
{
    lines++;bytes+=length($0)+1
    if(lines>8192 || bytes>1048576 || length($0)>4096 || index($0,"\r")) { bad=1;exit 2 }
    last=$0
    if(index($0,"GB_PHONE_LINK_ACTIVITY_END_V1 ")==1) {
        if(complete || index($0,trailer)!=1) { bad=1;next }
        code=substr($0,length(trailer)+1)
        if(code !~ /^(0|[1-9][0-9]?[0-9]?)$/ || code+0>255) { bad=1;next }
        complete++;producer=code+0;next
    }
    if(complete) { bad=1;next }
    if($1!="ACTIVITY" || ($2!=short && $2!=full))next
    headers++
    if($3 !~ /^[0-9a-fA-F]+$/) { malformed++;next }
    if(NF==5 && $4 ~ /^pid=[1-9][0-9]*$/ && substr($4,5)+0<=4194304 && $5=="userId=11") { running++;next }
    if(NF==6 && $4=="pid=(not" && $5=="running)" && $6=="userId=11") { not_running++;next }
    if(($5 ~ /^userId=[0-9]+$/ && $5!="userId=11") || ($6 ~ /^userId=[0-9]+$/ && $6!="userId=11")) { other_user++;next }
    malformed++
}
END {
    framed=(!bad && complete==1 && index(last,trailer)==1)
    valid=(framed && producer==0)
    status=!framed?"framing_refused":producer!=0?"producer_failed":malformed?"header_format_unknown":"headers_observed"
    # Partial/failed producers never yield qualified counts, including zero.
    printf "{\"schema_version\":1,\"status\":\"%s\",\"dump_complete\":%s,\"producer_exit_code\":",status,(valid?"true":"false")
    if(framed)printf "%d",producer;else printf "null"
    printf ",\"matching_headers\":%d,\"owner_running_headers\":%d,\"owner_not_running_headers\":%d,\"other_user_headers\":%d,\"malformed_target_headers\":%d}\n",(valid?headers:0),(valid?running:0),(valid?not_running:0),(valid?other_user:0),(valid?malformed:0)
    if(!valid || malformed)exit 2
}
