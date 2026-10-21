# ON-DEVICE fixed Phone Link feature-listener message-line counts only.
# Source: source-qr-payload-v1/findings.json (exact APK518884a1...). Unknown
# messages, map suffixes and exceptions are never exported. Raw logcat has no
# multiline record envelope: counts describe matching complete message lines.
# Caller binds current PID/UID/start/boot/APK independently before AND after.
# Zero counts never establish a feature state, enrollment or absence of errors.
#
# Producer template (all variables are validated/quoted by the owning caller):
# { timeout -k 1 5 logcat -d -v raw --pid="$pid" -t 2000 2>/dev/null;
#   producer_rc=$?;
#   printf '\nGB_PHONE_LINK_FEATURE_LOG_END_V1 %s %s\n' "$nonce" "$producer_rc";
# } | LC_ALL=C awk -v frame_nonce="$nonce" -f "$owned_reducer"
# Do not put the producer in a pipeline before capturing its exit status.
# This is a bounded retained-log snapshot, not full-history or fresh-event proof.
BEGIN {
    trailer="GB_PHONE_LINK_FEATURE_LOG_END_V1 "frame_nonce" ";producer=-1
    keys[1]="initial_status_load_entered"
    keys[2]="initial_status_listener_registered"
    keys[3]="initial_feature_states_loaded"
    keys[4]="initial_status_register_fetch_failed"
    keys[5]="initial_status_loader_cancelled"
    keys[6]="initial_status_listener_unregistered"
    keys[7]="initial_status_listener_unregister_failed"
    keys[8]="multidevice_sync_disabled"
    literals["loadInitialFeatureStatus()"] = 1
    literals["Successfully registered initial status listener"] = 2
    loaded="Successfully loaded initial feature states: "
    literals["Failed to register/fetch initial statuses"] = 4
    literals["Initial status loader job cancelled (likely due to broadcast from Multidevice)"] = 5
    literals["Successfully unregistered initial status listener"] = 6
    literals["Failed to unregister initial status listener"] = 7
    literals["MULTIDEVICE_SYNC is disabled"] = 8
    if(length(frame_nonce)!=32 || frame_nonce !~ /^[0-9a-f]+$/) { bad=1;exit 2 }
}
{
    lines++;bytes+=length($0)+1
    if(lines>4096 || bytes>262144 || length($0)>8192 || index($0,"\r") || index($0,sprintf("%c",0))) {
        bad=1;exit 2
    }
    last=$0
    if(index($0,"GB_PHONE_LINK_FEATURE_LOG_END_V1 ")==1) {
        if(complete || index($0,trailer)!=1) { bad=1;next }
        code=substr($0,length(trailer)+1)
        if(code !~ /^(0|[1-9][0-9]?[0-9]?)$/ || code+0>255) { bad=1;next }
        complete++;producer=code+0;next
    }
    if(complete) { bad=1;next }
    if($0 in literals)counts[literals[$0]]++
    else if(index($0,loaded)==1)counts[3]++
}
END {
    framed=(!bad && complete==1 && index(last,trailer)==1)
    valid=(framed && producer==0)
    status=!framed?"framing_refused":producer!=0?"producer_failed":"retained_log_counts_observed"
    printf "{\"schema_version\":1,\"status\":\"%s\",\"producer_complete\":%s,\"producer_exit_code\":",status,(framed?"true":"false")
    if(framed)printf "%d",producer;else printf "null"
    printf ",\"counts_valid\":%s,\"counts\":{",(valid?"true":"false")
    for(i=1;i<=8;i++)printf "%s\"%s\":%d",(i==1?"":","),keys[i],(valid?counts[i]:0)
    print "},\"full_history_verified\":false,\"identity_verified\":false,\"fresh_event_verified\":false,\"current_feature_state_verified\":false,\"enrollment_verified\":false,\"discovery_verified\":false,\"raw_messages_exported\":false}"
    if(!valid)exit 2
}
