# Scalar-only parser for a COMPLETE, single-package dumpsys package stream.
# Invocation: awk -v expected_package=<one fixed package> -v owner_user=11 \
#   -v frame_nonce=<32 lowerhex> -f this.awk
# Producer appends: GB_PHONE_LINK_PERMISSION_END_V1 <nonce> <exit code>
# Requires a natural top-level boundary after Packages, before that trailer.
# Reference Settings.java prints bare install rows for system user and explicit
# ', userId=N' overrides separately. No effective grant/fallback is inferred.
# Comparison source is AOSP Android16QPR2; installed-format equivalence unproved.
function uint(s,hi) { return s ~ /^(0|[1-9][0-9]*)$/ && length(s)<=10 && s+0<=hi }
function close_mode() {
    if(mode=="requested")requested_closed=1
    if(mode=="install")install_closed=1
    if(mode=="runtime" && current_user==11)runtime_closed=1
    mode=""
}
function owner_header(s, a,n,j,count) {
    n=split(s,a,/ +/)
    for(j=1;j<=n;j++)if(a[j]~/^installed=/){if(a[j]!~/^installed=(true|false)$/)return 0;count++}
    return count==1
}
function close_owner() { if(current_user==11)owner_closed=1;current_user=-1 }
function close_package() { close_mode();close_owner();if(target)package_closed=1;target=0 }
function flag(v) { return v?"true":"false" }
function nullable(seen,v) { return seen?flag(v):"null" }
# Called only for whitelist entries, with no raw values ever exported.
function grant(line,scope, name,rest,n,parts,user,key) {
    name=line;sub(/:.*/,"",name)
    if(!(name in wanted))return
    rest=substr(line,length(name)+1)
    if(index(rest,": granted=")!=1) { bad=1;return }
    rest=substr(rest,11);user=0
    n=split(rest,parts,", userId=")
    if(n>2 || (n==2 && (scope!="install" || !uint(parts[2],214) || parts[2]+0==0))) { bad=1;return }
    if(n==2)user=parts[2]+0
    rest=parts[1]
    # flags are ignored, but their bounded grammar must not absorb extra fields.
    if(index(rest,", flags=")==1) { bad=1;return }
    sub(/, flags=\[[ A-Za-z0-9_|]*\]$/,"",rest)
    if(rest!="true" && rest!="false") { bad=1;return }
    if(scope=="install") {
        key=name SUBSEP user
        if(key in install_seen) { bad=1;return }
        install_seen[key]=1;install_value[key]=(rest=="true")
    } else {
        if(n!=1) { bad=1;return }
        key=name SUBSEP current_user
        if(key in runtime_seen) { bad=1;return }
        runtime_seen[key]=1;runtime_value[key]=(rest=="true")
    }
}
BEGIN {
    names[1]="ACCESS_LOCAL_NETWORK";names[2]="BLUETOOTH_SCAN";names[3]="BLUETOOTH_CONNECT"
    names[4]="NEARBY_WIFI_DEVICES";names[5]="ACCESS_FINE_LOCATION";names[6]="ACCESS_COARSE_LOCATION"
    names[7]="INTERNET";names[8]="ACCESS_WIFI_STATE";names[9]="ACCESS_NETWORK_STATE"
    for(i=1;i<=9;i++){names[i]="android.permission."names[i];wanted[names[i]]=1}
    allowed=(expected_package=="com.google.ambient.streaming" || expected_package=="com.google.android.gms")
    trailer="GB_PHONE_LINK_PERMISSION_END_V1 "frame_nonce" ";producer=-1;current_user=-1
    if(!allowed || owner_user!="11" || length(frame_nonce)!=32 || frame_nonce!~/^[0-9a-f]+$/) { bad=1;exit 2 }
}
{
    lines++;bytes+=length($0)+1
    if(lines>32768 || bytes>4194304 || length($0)>8192 || index($0,"\r") || index($0,sprintf("%c",0))) { bad=1;exit 2 }
    last=$0
    if(index($0,"GB_PHONE_LINK_PERMISSION_END_V1 ")==1) {
        if(complete || index($0,trailer)!=1) { bad=1;next }
        code=substr($0,length(trailer)+1)
        if(!uint(code,255)) { bad=1;next }
        complete=1;producer=code+0;next
    }
    if(complete) { bad=1;next }
    if($0=="Packages:") {
        if(active)close_package()
        packages_sections++;if(packages_sections!=1)bad=1
        active=1;next
    }
    if($0~/^[^[:space:]]/) {
        if(active){close_package();active=0;if($0!~/:$/)bad=1}
        next
    }
    if(!active || $0~/^[[:space:]]*$/)next
    if($0~/^  Package /) {
        if(target)close_package()
        active_package_count++
        p=$2;sub(/^\[/,"",p);sub(/\]$/,"",p)
        if(NF!=3 || $1!="Package" || $2!="["expected_package"]" || $3!~/^\([0-9a-fA-F]+\):$/ || length($3)>19 || p!=expected_package || active_package_count!=1) { bad=1;target=0;next }
        target=1;target_count++;next
    }
    if(!target)next
    text=$0;sub(/^ +/,"",text);indent=length($0)-length(text)
    if(mode=="requested" && indent<=4)close_mode()
    if(mode=="install" && indent<=4)close_mode()
    if(mode=="runtime" && indent<=6)close_mode()
    if($0=="    requested permissions:") {
        if(requested_header++ || current_user!=-1 || install_header)bad=1
        mode="requested";next
    }
    if($0=="    install permissions:") {
        if(install_header++ || !requested_closed || current_user!=-1)bad=1
        mode="install";next
    }
    if($0~/^    User /) {
        close_mode();close_owner()
        u=$2;sub(/:$/,"",u)
        if($1!="User" || $2!=u":" || !uint(u,214) || NF<3 || !owner_header(text) || (u in users)) { bad=1;next }
        users[u]=1;current_user=u+0
        if(current_user==11)owner_seen++
        next
    }
    if($0=="      runtime permissions:") {
        if(current_user<0 || !requested_closed)bad=1
        if(current_user==11 && runtime_header++)bad=1
        mode="runtime";next
    }
    if(mode=="requested") {
        if(indent!=6 || text!~/^[A-Za-z0-9_.]+$/) { bad=1;next }
        if(text in wanted){if(text in requested)bad=1;requested[text]=1}
    } else if(mode=="install" || mode=="runtime") {
        if((mode=="install" && indent!=6) || (mode=="runtime" && indent!=8)) { bad=1;next }
        grant(text,mode)
    } else if(text=="requested permissions:" || text=="install permissions:" || text=="runtime permissions:")bad=1
}
END {
    framed=(!bad && complete==1 && index(last,trailer)==1)
    dump_complete=(framed && producer==0)
    scope_complete=(packages_sections==1 && active_package_count==1 && target_count==1 && package_closed && requested_header==1 && requested_closed && owner_seen==1 && owner_closed && runtime_header==1 && runtime_closed)
    valid=(dump_complete && scope_complete)
    status=bad?"format_or_scope_refused":!framed?"framing_refused":producer!=0?"producer_failed":!scope_complete?"incomplete_scopes":"permission_scopes_observed"
    printf "{\"schema_version\":1,\"status\":\"%s\",\"package\":",status
    if(allowed)printf "\"%s\"",expected_package;else printf "null"
    printf ",\"owner_user\":11,\"dump_complete\":%s,\"producer_exit_code\":",flag(dump_complete)
    if(framed)printf "%d",producer;else printf "null"
    printf ",\"active_package_scope_complete\":%s,\"requested_section_complete\":%s,\"owner_runtime_section_complete\":%s,\"install_scope\":\"system_user_entry\",\"permissions\":[",flag(valid),flag(valid&&requested_closed),flag(valid&&runtime_closed)
    for(i=1;i<=9;i++) {
        name=names[i];system_key=name SUBSEP 0;owner_key=name SUBSEP 11
        printf "%s{\"name\":\"%s\",\"requested\":%s,\"install_scope_granted\":%s,\"install_owner11_override_granted\":%s,\"runtime_owner11_granted\":%s}",(i>1?",":""),name,nullable(valid,requested[name]),nullable(valid&&(system_key in install_seen),install_value[system_key]),nullable(valid&&(owner_key in install_seen),install_value[owner_key]),nullable(valid&&(owner_key in runtime_seen),runtime_value[owner_key])
    }
    printf "],\"effective_grants_inferred\":false,\"appops_checked\":false,\"discovery_verified\":false,\"raw_fields_exported\":false}\n"
    if(!valid)exit 2
}
