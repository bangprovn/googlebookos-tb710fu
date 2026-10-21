// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

/** Pure fixed diagnostic pattern; no display state or captured pixels are retained. */
final class DisplayPattern {
    static final int SIZE=256, GRID=16, PHASES=3, SAMPLES=GRID*GRID, TOLERANCE=4;
    private static final int[] COLORS={0xffff0000,0xff00ff00,0xff0000ff,0xffffffff};
    static int color(int phase,int quadrant) {
        if(phase<0 || phase>=PHASES || quadrant<0 || quadrant>=4) throw new IllegalArgumentException();
        return COLORS[(quadrant+phase)%4];
    }
    static int sampleCoordinate(int index) {
        if(index<0 || index>=GRID) throw new IllegalArgumentException();
        return index*(SIZE/GRID)+(SIZE/GRID)/2;
    }
    static int expected(int phase,int x,int y) {
        if(x<0 || y<0 || x>=SIZE || y>=SIZE) throw new IllegalArgumentException();
        return color(phase,(x>=SIZE/2?1:0)+(y>=SIZE/2?2:0));
    }
    static boolean matches(int actual,int expected) {
        for(int shift=0;shift<=24;shift+=8)
            if(Math.abs(((actual>>>shift)&255)-((expected>>>shift)&255))>TOLERANCE) return false;
        return true;
    }
}
