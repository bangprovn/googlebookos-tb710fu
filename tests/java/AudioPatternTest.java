package org.googlebook.port.hardwareprobe;
import java.util.Random;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
public final class AudioPatternTest {
    private static void require(boolean value) {if(!value) throw new AssertionError();}
    public static void main(String[] args) throws Exception {
        final int rate=48000;
        short[] pattern=AudioPattern.generate(rate);
        short[] positive=new short[rate*2];
        Random random=new Random(1729);
        for(int i=0;i<positive.length;i++) positive[i]=(short)Math.round(random.nextGaussian()*12);
        for(int i=0;i<pattern.length;i++) positive[i+rate/3]+=(short)Math.round(pattern[i]*0.08);
        require(AudioPattern.detect(positive,positive.length,rate).matched);
        require(!AudioPattern.detect(new short[rate*2],rate*2,rate).matched);
        short[] noise=new short[rate*2];
        for(int i=0;i<noise.length;i++) noise[i]=(short)Math.round(random.nextGaussian()*1200);
        require(!AudioPattern.detect(noise,noise.length,rate).matched);
        short[] single=new short[rate*2];
        for(int i=0;i<single.length;i++) single[i]=(short)(1000*Math.sin(2*Math.PI*997*i/rate));
        require(!AudioPattern.detect(single,single.length,rate).matched);
        short[] reversed=new short[rate*2];
        for(int part=0;part<4;part++) for(int i=0;i<pattern.length/4;i++)
            reversed[rate/4+part*pattern.length/4+i]=pattern[(part^1)*pattern.length/4+i];
        require(!AudioPattern.detect(reversed,reversed.length,rate).matched);
        require(!AudioPattern.detect(positive,rate/2,rate).matched);
        require(!AudioPattern.detect(positive,positive.length,44100).matched);
        if(args.length>0) {
            require(args.length==1);
            byte[] wav=Files.readAllBytes(Paths.get(args[0]));
            require(wav.length==44+30720*2);
            ByteBuffer data=ByteBuffer.wrap(wav).order(ByteOrder.LITTLE_ENDIAN);
            require(data.getInt(24)==48000 && data.getShort(22)==1 && data.getShort(34)==16);
            short[] quietWave=new short[rate*3];int peak=0;
            for(int i=0;i<30720;i++) {short value=data.getShort(44+2*i);quietWave[rate/2+i]=value;peak=Math.max(peak,Math.abs((int)value));}
            require(peak>600 && peak<=655);
            require(AudioPattern.detect(quietWave,quietWave.length,rate).matched);
            System.out.println("PASS: independently generated quiet guest WAV matches Android detector");
        }
        System.out.println("PASS: delayed quiet known pattern detected; silence, noise, single tone, reversed sequence and invalid budgets rejected");
    }
}
