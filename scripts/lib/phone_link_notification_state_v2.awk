# Selected Phone Link notification only; reduce on device, never save raw input.
# Caller appends the nonce-bound numeric trailer unconditionally AFTER producer:
# GB_PHONE_LINK_NOTIFICATION_END_V2 <32 lowercase hex nonce> <exit 0..255>
# Requires -v frame_nonce=...; statuses distinguish producer exit, framing and
# record validation. Published title enums never prove discovery/pairing/RF.
function fail_record() { record_bad=1 }
function indent(s,p) { p=s;sub(/[^ ].*$/, "", p);return length(p) }
function spaces(n,s,i) { s="";for(i=0;i<n;i++)s=s" ";return s }
BEGIN {
    package="com.google.ambient.streaming";key="11|com.google.ambient.streaming|1|null|1110128"
    trailer="GB_PHONE_LINK_NOTIFICATION_END_V2 "frame_nonce" "
    state="unknown";producer=-1
    if(length(frame_nonce)!=32 || frame_nonce !~ /^[0-9a-f]+$/) { framing_bad=1;exit 2 }
}
{
    lines++;bytes+=length($0)+1
    if(lines>512 || bytes>65536 || length($0)>4096 || index($0,"\r")) { framing_bad=1;exit 2 }
    last=$0
    if(index($0,"GB_PHONE_LINK_NOTIFICATION_END_V2 ")==1) {
        if(complete || index($0,trailer)!=1) { framing_bad=1;next }
        code=substr($0,length(trailer)+1)
        if(code !~ /^(0|[1-9][0-9]?[0-9]?)$/ || code+0>255) { framing_bad=1;next }
        producer=code+0;complete++;next
    }
    if(complete) { framing_bad=1;next }
    if($0!="")data_lines++
    if($0=="error: no active notification matching key: "key)absent_lines++
    if(record_bad)next
    if($0 ~ /^[ ]*NotificationRecord\(/) {
        headers++;own=0;h=indent($0);s=substr($0,h+1)
        if(s !~ /^NotificationRecord\(0x[0-9a-fA-F]+: pkg=com\.google\.ambient\.streaming user=UserHandle\{11\} id=1 tag=null / || index(s," key="key": Notification(channel=device_link_channel_id ")==0) { fail_record();next }
        records++;if(records!=1) { fail_record();next }
        own=1;field=spaces(h+2);nested=spaces(2*(h+2));extra=nested"    ";phase=0;next
    }
    if(!own)next
    if($0==field"uid=1110128 userId=11") { uid++;next }
    if($0 ~ /^[ ]*uid=/ && phase==0) { fail_record();next }
    if($0==field"opPkg="package) { op++;next }
    if($0 ~ /^[ ]*opPkg=/ && phase==0) { fail_record();next }
    if($0==field"key="key) { keys++;next }
    if($0 ~ /^[ ]*key=/ && phase==0) { fail_record();next }
    if($0==field"notification=") {
        main_sections++;if(main_sections!=1 || uid!=1 || op!=1 || keys!=1) { fail_record();next }
        phase=1;next
    }
    if($0==field"publicNotification=") {
        public_sections++;if(phase!=3 || public_sections!=1) { fail_record();next }
        phase=4;next
    }
    if(phase==1 && $0==nested"extras={") { extras++;if(extras!=1) { fail_record();next };phase=2;next }
    if(phase==2 && $0==nested"}") { closed++;phase=3;next }
    if(phase==2) {
        if(index($0,extra"android.title=")==1) {
            titles++;if(titles!=1) { fail_record();next }
            if($0==extra"android.title=String (Looking for your nearby devices…)")state="discovering"
            else if($0==extra"android.title=String (Waiting for connections)")state="waiting"
            else if($0==extra"android.title=String (Connected)")state="connected"
            else state="unknown"
        } else if(index($0,extra)!=1) { fail_record();next }
        if($0 ~ /^[ ]*[a-zA-Z0-9_.]+=String / && $0 !~ /\)$/ && $0 !~ /String \[length=[0-9]+\]$/) { fail_record();next }
        next
    }
    if(phase!=4 && index($0,extra"android.title=")==1) { fail_record();next }
}
END {
    framed=(!framing_bad && complete==1 && index(last,trailer)==1)
    producer_complete=framed
    dump_complete=(framed && producer==0)
    valid=(dump_complete && !record_bad && headers==1 && records==1 && uid==1 && op==1 && keys==1 && main_sections==1 && extras==1 && closed==1 && public_sections==1 && phase==4 && titles==1)
    status="framing_refused"
    if(framed) {
        if(producer!=0) {
            status=(producer==1 && !record_bad && headers==0 && data_lines==1 && absent_lines==1)?"notification_absent":"producer_failed"
        } else if(valid)status=(state=="unknown"?"unrecognized_title":"title_observed")
        else if(!record_bad && headers==0 && data_lines==0)status="no_matching_record"
        else status="record_refused"
    }
    if(!valid)state="unknown"
    printf "{\"schema_version\":2,\"status\":\"%s\",\"state\":\"%s\",\"producer_complete\":%s,\"dump_complete\":%s,\"record_valid\":%s,\"producer_exit_code\":",status,state,(producer_complete?"true":"false"),(dump_complete?"true":"false"),(valid?"true":"false")
    if(producer_complete)printf "%d",producer;else printf "null"
    print "}"
    if(!valid || state=="unknown")exit 2
}
