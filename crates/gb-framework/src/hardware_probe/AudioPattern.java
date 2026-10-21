// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import java.util.ArrayList;
import java.util.List;

/** Known test signal and bounded detector; no Android dependencies or audio export. */
public final class AudioPattern {
    private static final double[] FREQUENCIES={997,1499,797,1197,1299,1699};
    public static short[] generate(int rate) {
        if(rate!=48000) throw new IllegalArgumentException("only bounded 48 kHz fixture supported");
        int segment=rate*160/1000,fade=Math.max(1,rate*5/1000);
        short[] result=new short[segment*4];
        for(int part=0;part<4;part++) for(int i=0;i<segment;i++) {
            double envelope=Math.min(1.0,Math.min((double)i/fade,(double)(segment-1-i)/fade));
            result[part*segment+i]=(short)Math.round(8191*envelope*Math.sin(2*Math.PI*FREQUENCIES[part%2]*i/rate));
        }
        return result;
    }
    public static final class Detection {
        public final boolean matched;
        public final int strongWindows,totalWindows;
        Detection(boolean matched,int strong,int total) {this.matched=matched;strongWindows=strong;totalWindows=total;}
    }
    private static final class Run {
        final int code;
        final int first;
        int last;
        Run(int code,int first,int last) {this.code=code;this.first=first;this.last=last;}
    }
    private static double power(short[] samples,int start,int length,double coefficient,double[] window) {
        double a=0,b=0;
        for(int i=0;i<length;i++) {
            double next=(samples[start+i]/32768.0)*window[i]+coefficient*a-b;
            b=a;a=next;
        }
        return Math.max(0,(a*a+b*b-coefficient*a*b)/(length*(double)length));
    }
    private static void append(List<Run> runs,int code,int first,int last,int hop,int rate) {
        if(code==0 || (last-first+1)*hop < rate*60/1000) return;
        if(!runs.isEmpty()) {
            Run previous=runs.get(runs.size()-1);
            if(previous.code==code && (first-previous.last)*hop<rate*70/1000) {previous.last=last;return;}
        }
        runs.add(new Run(code,first,last));
    }
    public static Detection detect(short[] samples,int count,int rate) {
        if(rate!=48000 || count<rate || count>rate*3 || count>samples.length) return new Detection(false,0,0);
        final int length=1536,hop=384;
        double[] coefficients=new double[FREQUENCIES.length],window=new double[length];
        for(int i=0;i<coefficients.length;i++) coefficients[i]=2*Math.cos(2*Math.PI*FREQUENCIES[i]/rate);
        for(int i=0;i<length;i++) window[i]=0.5-0.5*Math.cos(2*Math.PI*i/(length-1));
        List<Run> runs=new ArrayList<>();
        int previous=0,first=0,total=0,strong=0;
        for(int start=0;start+length<=count;start+=hop) {
            double[] energy=new double[FREQUENCIES.length];
            for(int i=0;i<energy.length;i++) energy[i]=power(samples,start,length,coefficients[i],window);
            double noise=(energy[2]+energy[3]+energy[4]+energy[5])/4;
            int code=0;
            if(energy[0]>1e-10 && energy[0]>energy[1]*6 && energy[0]>noise*12) code=1;
            if(energy[1]>1e-10 && energy[1]>energy[0]*6 && energy[1]>noise*12) code=2;
            if(code!=0) strong++;
            if(code!=previous) {append(runs,previous,first,total-1,hop,rate);previous=code;first=total;}
            total++;
        }
        append(runs,previous,first,total-1,hop,rate);
        for(int i=0;i+3<runs.size();i++) {
            boolean ok=true;
            for(int part=0;part<4;part++) {
                Run run=runs.get(i+part);
                ok &= run.code==part%2+1 && (run.last-run.first+1)*hop<=rate*270/1000;
                if(part>0) {
                    int delta=(run.first-runs.get(i+part-1).first)*hop;
                    ok &= delta>=rate*100/1000 && delta<=rate*240/1000;
                }
            }
            if(ok) return new Detection(true,strong,total);
        }
        return new Detection(false,strong,total);
    }
}
