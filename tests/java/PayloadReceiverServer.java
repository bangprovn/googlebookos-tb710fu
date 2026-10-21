package org.googlebook.port.terminalprobe;
import java.io.*;
import java.net.*;
import java.util.*;
/** Host-only interoperability test endpoint; no Android or firmware code. */
public final class PayloadReceiverServer {
    public static void main(String[] args) throws Exception {
        File directory=new File(args[0]);
        PayloadReceiver.Item item=new PayloadReceiver.Item("received.img",Long.parseLong(args[1]),args[2]);
        try(ServerSocket server=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))) {
            server.setSoTimeout(20000); System.out.println(server.getLocalPort());System.out.flush();
            try(Socket socket=server.accept()) {
                socket.setSoTimeout(5000);
                PayloadReceiver.receive(socket.getInputStream(),socket.getOutputStream(),
                    Collections.singletonMap("kernel",item),new HashSet<>(),directory);
            }
        }
    }
}
