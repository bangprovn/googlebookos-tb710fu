package org.googlebook.port.terminalprobe;

import java.util.*;
import android.system.virtualmachine.VirtualMachine;

/** Exercises owned fixtures only; device JNI/SELinux need physical validation. */
public final class ConsoleInspectionTest {
    public static void main(String[] args) throws Exception {
        for(String mode:new String[]{"denied","missing","bad_name","duplicate","success"}) {
            VirtualMachine.mode(mode);
            Map<String,String> result=ConsoleInspection.collect();
            boolean success=mode.equals("success");
            if(!Boolean.toString(true).equals(result.get("console_descriptors_closed"))
                    || !VirtualMachine.descriptorsClosed()
                    || success!=result.get("console_native_openpty").equals("passed")
                    || success!=result.get("console_roundtrip").equals("passed")
                    || success==result.containsKey("console_error"))
                throw new AssertionError(mode+": "+result);
            if(mode.equals("denied") && !result.get("console_error").contains("Permission denied"))
                throw new AssertionError("native cause was lost");
        }
        System.out.println("PASS: exact reflective callback, two-way fixture I/O, native failure, missing/invalid/duplicate callbacks, descriptor cleanup");
    }
}
