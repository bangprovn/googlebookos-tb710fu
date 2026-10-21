package org.googlebook.port.terminalprobe;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
public final class PayloadReceiverTest {
    private static byte[] frame(String id, long size, byte[] payload) throws Exception {
        ByteArrayOutputStream b=new ByteArrayOutputStream(); DataOutputStream d=new DataOutputStream(b);
        d.writeBytes("GBPF1\n");d.writeByte(id.length());d.writeBytes(id);d.writeLong(size);d.write(payload);d.writeBytes("GBEND\n");return b.toByteArray();
    }
    public static void main(String[] args) throws Exception {
        Path dir=Files.createTempDirectory("gb-protocol-");byte[] data="owned payload".getBytes("UTF-8");
        String sha=PayloadReceiver.hex(MessageDigest.getInstance("SHA-256").digest(data));
        Map<String,PayloadReceiver.Item> items=Collections.singletonMap("kernel",new PayloadReceiver.Item("kernel.img",data.length,sha));
        Set<String> done=new HashSet<>();ByteArrayOutputStream response=new ByteArrayOutputStream();
        PayloadReceiver.receive(new ByteArrayInputStream(frame("kernel",data.length,data)),response,items,done,dir.toFile());
        if (!Arrays.equals(Files.readAllBytes(dir.resolve("kernel.img")),data) || !done.contains("kernel")) throw new AssertionError("valid transfer");
        for (byte[] bad : new byte[][] {frame("../escape",data.length,data),frame("kernel",data.length+1,data),frame("kernel",data.length,new byte[data.length]),new byte[3]}) {
            Path child=Files.createDirectory(dir.resolve("case-"+UUID.randomUUID()));
            try {PayloadReceiver.receive(new ByteArrayInputStream(bad),new ByteArrayOutputStream(),items,new HashSet<>(),child.toFile());throw new AssertionError("accepted bad frame");}
            catch (IOException expected) {}
            try (java.util.stream.Stream<Path> files=Files.list(child)) {if(files.count()!=0)throw new AssertionError("partial publication");}
        }
        try {PayloadReceiver.receive(new ByteArrayInputStream(frame("kernel",data.length,data)),new ByteArrayOutputStream(),items,done,dir.toFile());throw new AssertionError("duplicate accepted");} catch(IOException expected) {}
        if(!Arrays.equals(Files.readAllBytes(dir.resolve("kernel.img")),data))throw new AssertionError("existing file changed");
        // A fresh receiver must also refuse a preexisting path, independently
        // of its in-memory completed set, including a symlink to another file.
        try {PayloadReceiver.receive(new ByteArrayInputStream(frame("kernel",data.length,data)),new ByteArrayOutputStream(),items,new HashSet<>(),dir.toFile());throw new AssertionError("existing destination replaced");} catch(IOException expected) {}
        Path links=Files.createDirectory(dir.resolve("symlink-case"));
        Files.createSymbolicLink(links.resolve("kernel.img"),dir.resolve("kernel.img"));
        try {PayloadReceiver.receive(new ByteArrayInputStream(frame("kernel",data.length,data)),new ByteArrayOutputStream(),items,new HashSet<>(),links.toFile());throw new AssertionError("symlink followed");} catch(IOException expected) {}
        if(!Arrays.equals(Files.readAllBytes(dir.resolve("kernel.img")),data))throw new AssertionError("existing target changed");
        System.out.println("PASS: valid, traversal, size, digest, truncation, duplicate and cleanup guards");
    }
}
