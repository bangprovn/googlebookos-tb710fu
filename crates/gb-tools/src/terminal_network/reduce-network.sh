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
function metadata(value, parts,n,key,v) {
    if(index(value,metaPrefix "|")==0) return;
    n=split(value,parts,"[|]");
    if(n!=4 || parts[1]!=metaPrefix || parts[4]!="E") refuse();
    key=parts[2];v=parts[3];
    if(key !~ /^(tc|tg|de|ce|hc|nb|tv|pr)$/ || seenField[key]++) refuse();
    if(key=="tv" && v=="-1") { observed[key]=-1;fields++;return }
    if(length(v)<1 || length(v)>5 || v !~ /^[0-9]+$/) refuse();
    if((key=="tc" || key=="tg" || key=="pr") && v !~ /^[01]$/) refuse();
    if((key=="de" || key=="ce") && v+0>255) refuse();
    if(key=="hc" && (length(v)!=3 || (v+0!=0 && (v+0<100 || v+0>599)))) refuse();
    if(key=="nb" && v+0>65536) refuse();
    if(key=="tv" && v+0>65535) refuse();
    observed[key]=v+0;fields++;
}

BEGIN {
    RS="\n";
    file=ENVIRON["GB_GUEST_META_PREFIX"];
    if((getline metaPrefix < file)!=1 || (getline extra < file)!=0) refuse(); close(file);
    if(length(metaPrefix)!=16 || metaPrefix !~ /^[0-9a-f]+$/) refuse();
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
    if(fields!=8 || !seenField["tc"] || !seenField["tg"] || !seenField["de"] || !seenField["ce"] || !seenField["hc"] || !seenField["nb"] || !seenField["tv"] || !seenField["pr"]) refuse();
    printf "{\"schema_version\":1,\"status\":\"owned_guest_network_observed\",\"fields\":8,\"nodes\":%d,\"eligible_text_nodes\":%d,\"curl_present\":%d,\"getent_present\":%d,\"resolver_exit\":%d,\"curl_exit\":%d,\"http_status\":%d,\"downloaded_bytes\":%d,\"tls_verify_result\":%d,\"metrics_parsed\":%d,\"exact_expected_prefix_matching\":true,\"unique_complete_full_rows\":true,\"input_performed\":false,\"raw_other_content_exported\":false,\"command_execution_verified\":false}\n",nodes,eligible,observed["tc"],observed["tg"],observed["de"],observed["ce"],observed["hc"],observed["nb"],observed["tv"],observed["pr"];

}
' "$1"
