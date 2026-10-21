# Bounded read-only Phone Link notification reduction for the pinned owner profile.
# Pipe ONLY the selected record (preferred) or the ordinary redacted dump; NEVER
# use --noredact and NEVER persist/forward raw input. The caller must append the
# exact completion sentinel ONLY after its diagnostic command exits zero.
# APK 518884a1...08e82f: channel device_link_channel_id, startForeground id=1.
# Fixed default resources: discovering=0x7f1201f9; waiting=0x7f1201fd;
# connected=0x7f1201f7. getString() means the dump has text, not original IDs.
# A title enum describes app-published status, not RF/peer/pairing/eligibility proof.
function reject() { invalid=1; exit 2 }
function indent(s, p) { p=s; sub(/[^ ].*$/, "", p); return length(p) }
function spaces(n, s,i) { s=""; for(i=0;i<n;i++)s=s" "; return s }
BEGIN {
    package="com.google.ambient.streaming"
    key="11|com.google.ambient.streaming|1|null|1110128"
    sentinel="GB_PHONE_LINK_NOTIFICATION_DUMP_COMPLETE_V1"
    state="unknown"
}
{
    lines++; bytes+=length($0)+1
    if(lines>512 || bytes>65536 || length($0)>4096 || index($0,"\r"))reject()
    last=$0
    if($0==sentinel) { complete++; next }
    if(complete)reject()
    if($0 ~ /^[ ]*NotificationRecord\(/) {
        own=0
        h=indent($0); s=substr($0,h+1)
        if(s !~ /^NotificationRecord\(0x[0-9a-fA-F]+: pkg=com\.google\.ambient\.streaming user=UserHandle\{11\} id=1 tag=null /)next
        # Header package/user/tag/id, complete exact key and channel all agree.
        if(index(s," key="key": Notification(channel=device_link_channel_id ")==0)next
        records++; if(records!=1)reject()
        own=1; field=spaces(h+2); nested=spaces(2*(h+2)); extra=nested"    "
        phase=0
        next
    }
    if(!own)next
    if($0==field"uid=1110128 userId=11") {uid++;next}
    if($0 ~ /^[ ]*uid=/ && phase==0)reject()
    if($0==field"opPkg="package) {op++;next}
    if($0 ~ /^[ ]*opPkg=/ && phase==0)reject()
    if($0==field"key="key) {keys++;next}
    if($0 ~ /^[ ]*key=/ && phase==0)reject()
    if($0==field"notification=") {
        main_sections++;if(main_sections!=1 || uid!=1 || op!=1 || keys!=1)reject()
        phase=1;next
    }
    if($0==field"publicNotification=") {
        public_sections++
        if(phase!=3 || public_sections!=1)reject()
        phase=4;next
    }
    if(phase==1 && $0==nested"extras={") {extras++;if(extras!=1)reject();phase=2;next}
    if(phase==2 && $0==nested"}") {closed++;phase=3;next}
    if(phase==2) {
        # Only one exact whole-field title may affect the enum. All body/other
        # extras are discarded; matching words inside them never count.
        if(index($0,extra"android.title=")==1) {
            titles++;if(titles!=1)reject()
            if($0==extra"android.title=String (Looking for your nearby devices…)" )state="discovering"
            else if($0==extra"android.title=String (Waiting for connections)")state="waiting"
            else if($0==extra"android.title=String (Connected)")state="connected"
            else state="unknown"
        } else if(index($0,extra)!=1)reject()
        # Reject multiline/unterminated String fields: dumped values are not an
        # escaped protocol, so continuations must never masquerade as fields.
        if($0 ~ /^[ ]*[a-zA-Z0-9_.]+=String / && $0 !~ /\)$/ && $0 !~ /String \[length=[0-9]+\]$/)reject()
        next
    }
    # A title outside the sole main extras block is not a usable title. A public
    # version may have its own extras, which are intentionally never inspected.
    if(phase!=4 && index($0,extra"android.title=")==1)reject()
}
END {
    framed=(!invalid && complete==1 && last==sentinel)
    valid=(framed && records==1 && uid==1 && op==1 && keys==1 && main_sections==1 && extras==1 && closed==1 && public_sections==1 && phase==4 && titles==1)
    if(!valid)state="unknown"
    printf "{\"schema_version\":1,\"state\":\"%s\",\"dump_complete\":%s}\n",state,(framed?"true":"false")
    if(!valid || state=="unknown")exit 2
}
