package android.system.virtualmachine;

import java.io.*;
import java.nio.file.*;

/** Host-owned reflection/descriptor fixture, never a VM or a real PTY. */
public final class VirtualMachine {
    private interface OpenPtyCallback {
        void apply(FileDescriptor master, FileDescriptor slave, byte[] name);
    }
    private static String mode;
    private static RandomAccessFile master, slave;
    public static void mode(String value) { mode=value; }
    public static boolean descriptorsClosed() throws IOException {
        return (master==null || !master.getFD().valid()) && (slave==null || !slave.getFD().valid());
    }
    private static void nativeOpenPtyRawNonblock(OpenPtyCallback callback) throws IOException {
        if(mode.equals("denied"))throw new IOException("openpty(): Permission denied");
        if(mode.equals("missing"))return;
        Path path=Files.createTempFile(Paths.get(System.getProperty("console.fixture.root")),"owned-", ".bin");
        master=new RandomAccessFile(path.toFile(),"rw");
        slave=new RandomAccessFile(path.toFile(),"rw");
        callback.apply(master.getFD(),slave.getFD(),
            (mode.equals("bad_name")?"/unexpected":"/dev/pts/123").getBytes("UTF-8"));
        if(mode.equals("duplicate"))callback.apply(master.getFD(),slave.getFD(),"/dev/pts/123".getBytes("UTF-8"));
    }
}
