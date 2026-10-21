# On-device fixed-component header SHAPES ONLY. Never export raw hashes, IDs,
# component strings, unknown field names/values, UI text or account/peer data.
# A complete shape is not identity, foreground, discovery or pairing proof.
# Append nonce-bound GB_PHONE_LINK_ACTIVITY_SHAPE_END_V1 <nonce> <exit> after
# the producer unconditionally. No input is persisted; <=4 headers/16tokens each.
function number(s,hi) { return s ~ /^(0|[1-9][0-9]*)$/ && length(s)<=10 && s+0<=hi }
function role(token,position, s,n,k) {
    if(position==1)return "activity_keyword"
    if(position==2)return token==short?"component_short":"component_full"
    if(position==3 && token ~ /^[0-9a-fA-F]+$/ && length(token)<=16)return "opaque_hex"
    if(index(token,"pid=")==1) {
        pid_fields++
        s=substr(token,5)
        if(number(s,4194304) && s+0>0)return "pid_positive"
        if(s=="(not")return "pid_not_running_start"
        return "pid_malformed"
    }
    if(token=="running)")return "pid_not_running_end"
    if(index(token,"userId=")==1) {
        user_fields++;s=substr(token,8)
        if(!number(s,214))return "user_id_malformed"
        if(s=="11") { owner_user_fields++;return "user_id_owner" }
        return "user_id_other"
    }
    if(index(token,"uid=")==1) {
        uid_fields++;s=substr(token,5)
        if(!number(s,2147483647))return "uid_malformed"
        if(s=="1110128") { owner_uid_fields++;return "uid_owner" }
        return "uid_other"
    }
    if(index(token,"displayId=")==1) {
        display_fields++;s=substr(token,11)
        if(s=="N/A")return "display_unavailable"
        n=split(s,k,"\\(type=")
        if(n==2 && number(k[1],2147483647)) {
            if(k[2]=="INTERNAL)")return "display_internal"
            if(k[2]=="EXTERNAL)")return "display_external"
            if(k[2]=="VIRTUAL)")return "display_virtual"
            if(k[2]=="OVERLAY)")return "display_overlay"
            if(k[2]=="WIFI)")return "display_wifi"
            if(k[2]=="UNKNOWN)")return "display_unknown"
        }
        if(number(s,2147483647))return "display_plain_numeric"
        return "display_malformed"
    }
    if(token ~ /^(taskId|rootTaskId)=[0-9]+$/)return "task_numeric"
    if(token ~ /^(visible|resumed|topResumed)=(true|false)$/)return "known_boolean"
    if(token ~ /^state=(INITIALIZING|RESUMED|PAUSING|PAUSED|STOPPING|STOPPED|FINISHING|DESTROYING|DESTROYED|RESTARTING_PROCESS)$/)return "known_state"
    unknown++;return "unknown"
}
BEGIN {
    short="com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity"
    full="com.google.ambient.streaming/com.google.ambient.streaming.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity"
    trailer="GB_PHONE_LINK_ACTIVITY_SHAPE_END_V1 "frame_nonce" ";producer=-1
    if(length(frame_nonce)!=32 || frame_nonce !~ /^[0-9a-f]+$/) { bad=1;exit 2 }
}
{
    lines++;bytes+=length($0)+1
    if(lines>8192 || bytes>1048576 || length($0)>4096 || index($0,"\r")) { bad=1;exit 2 }
    last=$0
    if(index($0,"GB_PHONE_LINK_ACTIVITY_SHAPE_END_V1 ")==1) {
        if(complete || index($0,trailer)!=1) { bad=1;next }
        code=substr($0,length(trailer)+1)
        if(code !~ /^(0|[1-9][0-9]?[0-9]?)$/ || code+0>255) { bad=1;next }
        complete++;producer=code+0;next
    }
    if(complete) { bad=1;next }
    if($1!="ACTIVITY" || ($2!=short && $2!=full))next
    headers++
    if(headers>4 || NF>16 || NF<3) { bad=1;exit 2 }
    pid_fields=user_fields=owner_user_fields=uid_fields=owner_uid_fields=display_fields=unknown=0
    roles=""
    for(i=1;i<=NF;i++)roles=roles (i>1?",":"")"\""role($i,i)"\""
    shapes[headers]="{\"field_count\":"NF",\"roles\":["roles"],\"pid_fields\":"pid_fields",\"user_fields\":"user_fields",\"owner_user_fields\":"owner_user_fields",\"uid_fields\":"uid_fields",\"owner_uid_fields\":"owner_uid_fields",\"display_fields\":"display_fields",\"unknown_tokens\":"unknown"}"
}
END {
    framed=(!bad && complete==1 && index(last,trailer)==1);valid=(framed && producer==0)
    status=!framed?"framing_refused":producer!=0?"producer_failed":headers?"shape_observed":"no_matching_header"
    printf "{\"schema_version\":1,\"status\":\"%s\",\"dump_complete\":%s,\"producer_exit_code\":",status,(valid?"true":"false")
    if(framed)printf "%d",producer;else printf "null"
    printf ",\"matching_headers\":%d,\"shapes\":[",(valid?headers:0)
    if(valid)for(i=1;i<=headers;i++)printf "%s%s",(i>1?",":""),shapes[i]
    print "],\"identity_verified\":false,\"foreground_verified\":false,\"raw_fields_exported\":false}"
    if(!valid)exit 2
}
