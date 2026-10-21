#!/system/bin/sh
# Read-only reducer for one owned UIAutomator XML file. No raw text is emitted.
# Native control inventory only. No text/title/canary output; one INPUT argument.
set -eu
[ "$#" -eq 1 ] || exit 2
[ -f "$1" ] && [ ! -L "$1" ] || exit 2
bytes=$(wc -c < "$1")
[ "$bytes" -gt 0 ] && [ "$bytes" -le 2097152 ] || exit 2
awk '
function refuse() { bad=1; print "UI redaction rejected input" > "/dev/stderr"; exit 2 }
BEGIN {
    RS="<";quote=sprintf("%c",39);
    attributePattern="^[[:space:]]*[A-Za-z_][A-Za-z0-9_.:-]*=(\"[^\"]*\"|" quote "[^" quote "]*" quote ")";
    print "<gb-ui><hierarchy>";
}
NR==1 { if ($0 !~ /^[[:space:]]*$/) refuse(); next }
{
    tag=$0; sub(/[[:space:]]*$/, "", tag);
    if (length(tag)>2097152 || substr(tag,length(tag),1)!=">") refuse();
    tag=substr(tag,1,length(tag)-1);
    if (tag ~ /^\?xml[[:space:]]/ && !started && nodes==0) next;
    if (tag ~ /^hierarchy([[:space:]]|$)/ && !started) { started=1; next }
    if (tag=="/hierarchy" && started && !finished && depth==0) { finished=1; next }
    if (!started || finished) refuse();
    if (tag=="/node") { if(depth<=0) refuse(); depth--; print "</node>"; next }
    if (tag !~ /^node([[:space:]]|$)/) refuse();
    nodes++; if(nodes>50000) refuse();
    rest=substr(tag,5); selfclose=(rest ~ /\/[[:space:]]*$/);
    if(selfclose) sub(/\/[[:space:]]*$/, "", rest);
    for(key in seen) delete seen[key];
    attrs="";
    while(rest !~ /^[[:space:]]*$/) {
        if(!match(rest,attributePattern)) refuse();
        attr=substr(rest,1,RLENGTH); rest=substr(rest,RLENGTH+1);
        sub(/^[[:space:]]*/, "", attr); eq=index(attr,"=");
        key=substr(attr,1,eq-1); value=substr(attr,eq+2,length(attr)-eq-2);
        if(seen[key]++) refuse();
        if(key=="package") value=(value=="com.android.virtualization.terminal" ? value : "redacted.foreign");
        else if(key=="class") value=(value=="android.webkit.WebView" || value=="android.widget.EditText" || value=="android.widget.Button" || value=="android.widget.ImageButton" || value=="android.widget.ImageView" || value=="android.widget.TextView" || value=="android.app.ActionBar$Tab" ? value : "android.view.View");
        else if(key=="focused" || key=="password" || key=="enabled" || key=="clickable" || key=="selected" || key=="focusable") { if(value!="true" && value!="false") refuse() }
        else if(key=="bounds") { if(length(value)>64 || value !~ /^\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]$/) refuse() }
        else if(key=="content-desc") { if(value!="Display options" && value!="Close display controls" && value!="Cursor" && value!="Add tab" && value!="Close tab") continue }
        else continue;
        attrs=attrs " " key "=\"" value "\"";
    }
    if(selfclose) print "<node" attrs "/>";
    else { depth++; if(depth>512) refuse(); print "<node" attrs ">" }
}
END {
    if(bad) exit 2;
    if(!started || !finished || depth!=0) { print "UI redaction incomplete" > "/dev/stderr"; exit 2 }
    print "</hierarchy><gb-meta complete=\"true\" node_count=\"" (nodes+0) "\"/></gb-ui>";
}
' "$1"
