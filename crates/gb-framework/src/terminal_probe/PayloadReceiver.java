package org.googlebook.port.terminalprobe;

import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Fixed, length-bounded file frames. Input never supplies a destination path. */
public final class PayloadReceiver {
    public static final class Item {
        public final String filename, sha256;
        public final long bytes;
        public Item(String filename, long bytes, String sha256) {
            if (!filename.matches("[a-zA-Z0-9_.-]{1,64}") || filename.equals(".")
                    || filename.equals("..") || bytes < 1 || bytes > 4L * 1024 * 1024 * 1024
                    || !sha256.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("item");
            this.filename = filename; this.bytes = bytes; this.sha256 = sha256;
        }
    }
    public static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte v : b) s.append(String.format(Locale.ROOT, "%02x", v & 255));
        return s.toString();
    }
    public static String receive(InputStream input, OutputStream output,
            Map<String, Item> items, Set<String> completed, File directory) throws Exception {
        DataInputStream in = new DataInputStream(input);
        byte[] magic = new byte[6]; in.readFully(magic);
        if (!Arrays.equals(magic, "GBPF1\n".getBytes("US-ASCII"))) throw new IOException("frame magic");
        int n = in.readUnsignedByte();
        if (n < 1 || n > 16) throw new IOException("frame ID length");
        byte[] name = new byte[n]; in.readFully(name);
        String id = new String(name, "US-ASCII");
        Item item = items.get(id);
        if (item == null || completed.contains(id) || in.readLong() != item.bytes)
            throw new IOException("unknown, repeated or wrong-size payload");
        Path destination = new File(directory, item.filename).toPath();
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) throw new IOException("destination exists");
        boolean created = false;
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            // This directory is a new, unpublished profile. Exclusive creation
            // avoids overwrites without requiring app-domain hardlink permission.
            // The complete verified profile is published by one directory rename.
            try (FileChannel file = FileChannel.open(destination, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE)) {
                created = true;
                OutputStream sink = Channels.newOutputStream(file);
                byte[] buffer = new byte[1024 * 1024]; long left = item.bytes;
                while (left > 0) {
                    int got = in.read(buffer, 0, (int)Math.min(buffer.length, left));
                    if (got < 0) throw new EOFException("truncated payload");
                    sink.write(buffer, 0, got); hash.update(buffer, 0, got); left -= got;
                }
                byte[] end = new byte[6]; in.readFully(end);
                if (!Arrays.equals(end, "GBEND\n".getBytes("US-ASCII"))
                        || !hex(hash.digest()).equals(item.sha256)) throw new IOException("payload integrity");
                file.force(true);
            }
            created = false;
            completed.add(id);
            DataOutputStream response = new DataOutputStream(output);
            response.writeUTF("OK " + id + " " + item.sha256); response.flush();
            return id;
        } finally {
            if (created) Files.deleteIfExists(destination);
        }
    }
}
