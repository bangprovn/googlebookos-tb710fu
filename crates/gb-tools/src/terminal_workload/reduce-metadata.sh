#!/system/bin/sh
# Exact nonce-bound guest metadata only. Private XML/other text stays on Android.
# Grammar derives from pinned a17edf redact-ui-controls.sh; no entity decoding.
set -eu
export LC_ALL=C
refuse() { echo 'Guest metadata refused' >&2; exit 2; }
[ "$#" -eq 2 ] || refuse
for path in "$1" "$2"; do
    [ -f "$path" ] && [ ! -L "$path" ] || refuse
    [ "$(stat -c %a "$path" 2>/dev/null)" = 600 ] || refuse
    [ "$(stat -c %u "$path" 2>/dev/null)" = "$(id -u)" ] || refuse
done
bytes=$(wc -c < "$1")
[ "$bytes" -gt 0 ] && [ "$bytes" -le 2097152 ] || refuse
[ "$(wc -c < "$2")" -eq 17 ] || refuse
# Load only the private owned prefix by getline; never emit it or other text.
GB_GUEST_META_PREFIX="$2" awk '
function refuse() { bad=1; print "Guest metadata refused" > "/dev/stderr"; exit 2 }
function xmlscalar(n) { return n==9 || n==10 || n==13 || (n>=32 && n<=55295) || (n>=57344 && n<=65533) || (n>=65536 && n<=1114111) }
function entities(value,  i,j,item,k,n,d,digits) {
    i=1;
    while(i<=length(value)) {
        if(substr(value,i,1)!="&") { i++; continue }
        j=index(substr(value,i),";"); if(j==0 || j>16) return 0;
        item=substr(value,i+1,j-2);
        if(item=="amp" || item=="lt" || item=="gt" || item=="quot" || item=="apos") { i+=j; continue }
        n=0;
        if(item ~ /^#[0-9]+$/) {
            digits=substr(item,2); if(length(digits)>7) return 0;
            for(k=1;k<=length(digits);k++) n=n*10+substr(digits,k,1);
        } else if(item ~ /^#x[0-9a-fA-F]+$/) {
            digits=tolower(substr(item,3)); if(length(digits)>6) return 0;
            for(k=1;k<=length(digits);k++) n=n*16+index("0123456789abcdef",substr(digits,k,1))-1;
        } else return 0;
        if(!xmlscalar(n)) return 0;
        i+=j;
    }
    return 1;
}
function bounds(value,  v,n,a,i) {
    if(length(value)>64 || value !~ /^\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]$/) refuse();
    v=value; gsub(/\]\[/,",",v); gsub(/[\[\]]/,"",v); n=split(v,a,","); if(n!=4) refuse();
    for(i=1;i<=4;i++) if(length(a[i])>5 || a[i]+0>16384) refuse();
    if(a[1]+0>a[3]+0 || a[2]+0>a[4]+0) refuse();
    return a[3]+0>a[1]+0;
}
function metadata(value, parts,n,key,v,i) {
    # Match the complete frame introducer, not a nonce substring in the success marker.
    if(index(value,metaPrefix "|")==0) return;
    n=split(value,parts,"[|]");
    if(n!=4 || parts[1]!=metaPrefix || parts[4]!="E") refuse();
    key=parts[2];v=parts[3];
    if(key !~ /^(b[01]|k[0-4]|s[0-3]|o|a|m)$/ || seenField[key]++) refuse();
    if(key ~ /^b/) { if(length(v)!=18 || v !~ /^[0-9a-f-]+$/) refuse() }
    else if(key ~ /^k/) { if(length(v)>16 || (length(v)>0 && v !~ /^[A-Za-z0-9_.+-]+$/)) refuse() }
    else if(key ~ /^s/) { if(length(v)!=16 || v !~ /^[0-9a-f]+$/) refuse() }
    else if(key=="m") { if(length(v)>8 || v !~ /^[1-9][0-9]*$/ || v+0>67108864) refuse() }
    else if(length(v)<1 || length(v)>16 || v !~ /^[A-Za-z0-9_.+-]+$/) refuse();
    fragment[key]=v;fields++;
}
function normalize(i,k,v,n,u) {
    for(i=0;i<2;i++) if(!seenField["b" i]) refuse();
    for(i=0;i<5;i++) if(!seenField["k" i]) refuse();
    for(i=0;i<4;i++) if(!seenField["s" i]) refuse();
    if(!seenField["o"] || !seenField["a"] || !seenField["m"]) refuse();
    observed["boot"]=fragment["b0"] fragment["b1"];
    v=observed["boot"];n=split(v,u,"-");
    if(length(v)!=36 || n!=5 || length(u[1])!=8 || length(u[2])!=4 || length(u[3])!=4 || length(u[4])!=4 || length(u[5])!=12) refuse();
    for(i=1;i<=5;i++) if(u[i] !~ /^[0-9a-f]+$/) refuse();
    for(i=0;i<5;i++) {
        v=fragment["k" i];
        if(i>0 && length(v)>0 && length(fragment["k" (i-1)])!=16) refuse();
        observed["kernel"]=observed["kernel"] v;
    }
    if(observed["kernel"] !~ /^[0-9][A-Za-z0-9_.+-]*$/) refuse();
    for(i=0;i<4;i++) observed["sha256"]=observed["sha256"] fragment["s" i];
    observed["os"]=fragment["o"];observed["arch"]=fragment["a"];observed["mem_kib"]=fragment["m"];
}

BEGIN {
    RS="\n";
    file=ENVIRON["GB_GUEST_META_PREFIX"];
    if((getline metaPrefix < file)!=1 || (getline extra < file)!=0) refuse(); close(file);
    if(length(metaPrefix)!=16 || metaPrefix !~ /^[0-9a-f]+$/) refuse();
    knownHash="30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58";
    RS="<";
    depth=0; own[0]=1; web[0]=0; editor[0]=0;
    quote=sprintf("%c",39);
    attributePattern="^[[:space:]]+[A-Za-z_][A-Za-z0-9_.:-]*=(\"[^\"]*\"|" quote "[^" quote "]*" quote ")";
    declarationPattern="^\\?xml[[:space:]]+version=(\"1[.]0\"|" quote "1[.]0" quote ")" \
        "([[:space:]]+encoding=(\"UTF-8\"|" quote "UTF-8" quote "))?" \
        "([[:space:]]+standalone=(\"yes\"|" quote "yes" quote "))?[[:space:]]*\\?$";
}
NR==1 { if($0 !~ /^[[:space:]]*$/) refuse(); next }
{
    tag=$0; sub(/[[:space:]]*$/, "",tag);
    if(length(tag)>2097152 || substr(tag,length(tag),1)!=">") refuse();
    tag=substr(tag,1,length(tag)-1);
    if(tag ~ /^\?xml[[:space:]]/ && !started && nodes==0 && !declaration) {
        if(length(tag)>256 || tag !~ declarationPattern) refuse(); declaration=1; next;
    }
    if(tag ~ /^hierarchy([[:space:]]|$)/ && !started) {
        if(tag !~ /^hierarchy([[:space:]]+rotation="[0-3]")?[[:space:]]*$/) refuse();
        started=1; next;
    }
    if(tag=="/hierarchy" && started && !finished && depth==0) { finished=1; next }
    if(!started || finished) refuse();
    if(tag=="/node") { if(depth<=0) refuse(); depth--; next }
    if(tag !~ /^node([[:space:]]|$)/) refuse();
    nodes++; if(nodes>4096 || depth+1>64) refuse();
    rest=substr(tag,5); selfclose=(rest ~ /\/[[:space:]]*$/);
    if(selfclose) sub(/\/[[:space:]]*$/, "",rest);
    for(key in seen) delete seen[key];
    for(key in attr) delete attr[key];
    while(rest !~ /^[[:space:]]*$/) {
        if(!match(rest,attributePattern)) refuse();
        item=substr(rest,1,RLENGTH); rest=substr(rest,RLENGTH+1);
        sub(/^[[:space:]]*/,"",item); eq=index(item,"=");
        key=substr(item,1,eq-1); value=substr(item,eq+2,length(item)-eq-2);
        if(seen[key]++ || !entities(value) || value ~ /[[:cntrl:]]/) refuse();
        if(key=="text" && length(value)>4096) refuse();
        if(key=="package" || key=="class" || key=="bounds" || key=="text") attr[key]=value;
    }
    if(!seen["package"] || !seen["class"] || !seen["bounds"]) refuse();
    positiveWidth=bounds(attr["bounds"]);
    isOwn=own[depth] && attr["package"]=="com.android.virtualization.terminal";
    isWeb=(attr["class"]=="android.webkit.WebView");
    isEditor=editor[depth] || attr["class"]=="android.widget.EditText";
    if(isOwn && web[depth] && !isWeb && !isEditor && positiveWidth && length(attr["text"])>0) {
        eligible++; textBytes+=length(attr["text"]);
        if(textBytes>262144) refuse();
        metadata(attr["text"]);
    }
    if(!selfclose) {
        depth++; if(depth>64) refuse();
        own[depth]=isOwn; web[depth]=web[depth-1] || (isOwn && isWeb); editor[depth]=isEditor;
    }
}
END {
    if(bad) exit 2;
    if(!started || !finished || depth!=0) { print "Guest metadata refused" > "/dev/stderr"; exit 2 }
    if(fields!=14) refuse();
    normalize();
    printf "{\"schema_version\":1,\"status\":\"owned_guest_metadata_observed\",\"complete\":true,\"fields\":6,\"nodes\":%d,\"eligible_text_nodes\":%d,\"eligible_text_bytes\":%d,\"guest_boot_id\":\"%s\",\"kernel_os\":\"%s\",\"kernel_release\":\"%s\",\"architecture\":\"%s\",\"memtotal_kib\":%d,\"sha256_1mib_zeros\":\"%s\",\"known_answer_sha256_matches\":%s,\"exact_expected_prefix_matching\":true,\"unique_complete_full_rows\":true,\"xml_entities_decoded\":false,\"input_performed\":false,\"raw_other_content_exported\":false,\"command_execution_verified\":false,\"full_port_verified\":false}\n",nodes,eligible,textBytes,observed["boot"],observed["os"],observed["kernel"],observed["arch"],observed["mem_kib"]+0,observed["sha256"],(observed["sha256"]==knownHash ? "true" : "false");
}
' "$1"
