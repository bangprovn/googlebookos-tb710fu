package org.googlebook.port.terminalprobe;

import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Transient PTY test using exactly the installed AVF JNI; no VM or app files. */
final class ConsoleInspection {
    private static final byte[] REQUEST = "GBPTY1\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] REPLY = "GBPTY2\n".getBytes(StandardCharsets.US_ASCII);

    private static void exchange(OutputStream writer, InputStream input, byte[] bytes) throws Exception {
        // The installed JNI sets raw mode and makes the master nonblocking.
        // Write each tiny message before reading from its otherwise idle peer.
        writer.write(bytes);
        byte[] received = new byte[bytes.length]; int total=0;
        long deadline=System.nanoTime()+200000000L;
        while (total<received.length && System.nanoTime()<deadline) {
            try {
                int n=input.read(received,total,received.length-total);
                if(n<0)throw new EOFException("PTY closed during roundtrip");
                total+=n;
            } catch(IOException e) {
                if(System.nanoTime()>=deadline)throw e;
                Thread.sleep(5);
            }
        }
        if(total!=received.length || !Arrays.equals(bytes,received))
            throw new IOException("PTY roundtrip mismatch or deadline");
    }

    static Map<String,String> collect() {
        Map<String,String> result=new LinkedHashMap<>();
        final FileDescriptor[] descriptors=new FileDescriptor[2];
        FileInputStream[] readers=new FileInputStream[2];
        FileOutputStream[] writers=new FileOutputStream[2];
        result.put("console_native_openpty","failed");
        result.put("console_roundtrip","unverified");
        try {
            Class<?> vm=Class.forName("android.system.virtualmachine.VirtualMachine");
            Class<?> callback=Class.forName("android.system.virtualmachine.VirtualMachine$OpenPtyCallback");
            Object receiver=Proxy.newProxyInstance(callback.getClassLoader(),new Class<?>[]{callback},
                new InvocationHandler() { @Override public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    if(!method.getName().equals("apply") || args==null || args.length!=3)
                        throw new IllegalArgumentException("unexpected PTY callback");
                    if(descriptors[0]!=null || descriptors[1]!=null)
                        throw new IllegalStateException("duplicate PTY callback");
                    descriptors[0]=(FileDescriptor)args[0]; descriptors[1]=(FileDescriptor)args[1];
                    byte[] name=(byte[])args[2];
                    if(descriptors[0]==null || descriptors[1]==null || !descriptors[0].valid()
                            || !descriptors[1].valid() || descriptors[0]==descriptors[1]
                            || name==null || name.length>128
                            || !new String(name,StandardCharsets.UTF_8).trim().matches("/dev/pts/[0-9]{1,8}"))
                        throw new IOException("invalid PTY descriptors or name");
                    return null;
                }});
            Method open=vm.getDeclaredMethod("nativeOpenPtyRawNonblock",callback);
            open.setAccessible(true); open.invoke(null,receiver);
            if(descriptors[0]==null || descriptors[1]==null)throw new IOException("missing PTY callback");
            result.put("console_native_openpty","passed");
            for(int i=0;i<2;i++) {
                readers[i]=new FileInputStream(descriptors[i]);
                writers[i]=new FileOutputStream(descriptors[i]);
            }
            exchange(writers[0],readers[1],REQUEST);
            exchange(writers[1],readers[0],REPLY);
            result.put("console_roundtrip","passed");
        } catch(Throwable e) {
            if(e instanceof InvocationTargetException && e.getCause()!=null)e=e.getCause();
            String message=e.getClass().getSimpleName()+": "+String.valueOf(e.getMessage());
            result.put("console_error",message.substring(0,Math.min(message.length(),512)).replace('\n',' ').replace('\r',' '));
        } finally {
            boolean closed=true;
            // Retain all stream wrappers until cleanup: a finalizer must not
            // close a shared descriptor between the two roundtrips.
            for(int i=0;i<2;i++) {
                try { if(readers[i]!=null)readers[i].close(); }
                catch(IOException e) { closed=false; }
                try { if(writers[i]!=null)writers[i].close(); }
                catch(IOException e) { closed=false; }
            }
            for(FileDescriptor descriptor:descriptors) {
                if(descriptor!=null && descriptor.valid()) {
                    try { new FileInputStream(descriptor).close(); }
                    catch(IOException e) { closed=false; }
                }
            }
            result.put("console_descriptors_closed",Boolean.toString(closed));
        }
        return result;
    }
}
