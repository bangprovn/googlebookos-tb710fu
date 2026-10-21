#!/system/bin/sh
# Fixed read-only entrypoint. Init's security transition sanitizes LD_*; set
# this service's trusted private environment in-domain before the final exec.
[ "$#" -eq 0 ] || exit 64
export CLASSPATH=/system_ext/framework/gb-qesdsys-host.jar
export LD_LIBRARY_PATH=/system_ext/lib64/gb-qesdsys
/system/bin/log -p i -t GB-QESDSYS "trusted launcher entered; fixed private runtime selected" || :
exec /system/bin/app_process64 -Ximage:/system_ext/gb-qesdsys/no-boot-image.art -Xnoimage-dex2oat -Xusejit:false -Xint /system/bin --nice-name=gb-qesdsys org.googlebook.port.qesdsys.QesdSysHost /system_ext/gb-qesdsys/FrameworksUtilsSysService.apk e7de3d389b3a04b7cba5ae7007cc3e7e30091e9d5e17573e171039e5165570a8 Dell/mica/mica:17/CL3B.260622.273.R1/16471258:user/release-keys
