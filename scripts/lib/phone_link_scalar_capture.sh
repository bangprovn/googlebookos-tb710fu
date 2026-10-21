#!/system/bin/sh
# Fixed read-only producers only. Run ON DEVICE with a pinned owned awk reducer.
# No temporary files, raw forwarding, log dump, private text or settings changes.
# Usage: sh SCRIPT notification|activity <32hex frame nonce> <absolute reducer>
[ "$#" -eq 3 ] || exit 2
mode=$1
frame_nonce=$2
reducer=$3
[ "${#frame_nonce}" -eq 32 ] || exit 2
case "$frame_nonce" in *[!0-9a-f]*) exit 2;; esac
case "$reducer" in /*) ;; *) exit 2;; esac
case "$reducer" in *[!A-Za-z0-9_./-]*) exit 2;; esac
[ "${#reducer}" -le 256 ] && [ -f "$reducer" ] && [ ! -L "$reducer" ] || exit 2
case "$mode" in
 notification)
  {
   timeout -s KILL 2 cmd notification get '11|com.google.ambient.streaming|1|null|1110128'
   producer_rc=$?
   printf '\nGB_PHONE_LINK_NOTIFICATION_END_V2 %s %s\n' "$frame_nonce" "$producer_rc"
  } 2>/dev/null | LC_ALL=C awk -v frame_nonce="$frame_nonce" -f "$reducer"
  ;;
 activity)
  {
   # The outer2s limit expires before dumpsys's normal10s internal deadline;
   # a killed partial producer cannot be relabeled complete by a successful awk.
   timeout -s KILL 2 dumpsys activity top
   producer_rc=$?
   printf '\nGB_PHONE_LINK_ACTIVITY_END_V1 %s %s\n' "$frame_nonce" "$producer_rc"
  } 2>/dev/null | LC_ALL=C awk -v frame_nonce="$frame_nonce" -f "$reducer"
  ;;
 *) exit 2;;
esac
