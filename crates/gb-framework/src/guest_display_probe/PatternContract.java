package org.googlebook.port.guestdisplay;

/** Pure bounded policy; it never receives a desktop image or arbitrary expected colors. */
public final class PatternContract {
    public static final int[][] COLORS = {{19,67,139},{203,37,91},{47,181,113},{211,173,53}};
    public static final int TOLERANCE = 8;
    private PatternContract() {}
    public static void require(boolean v) {
        if (!v) throw new IllegalArgumentException("contract refused");
    }
    public static void bounds(int l, int t, int r, int b) {
        require(l >= 0 && t >= 0 && r <= 32768 && b <= 32768);
        require(r-l >= 32 && b-t >= 32 && r-l <= 4096 && b-t <= 4096);
        require((long)(r-l)*(b-t) <= 8L*1024*1024);
    }
    public static void owner(int user, int uid) {
        require(user >= 0 && user <= 214 && uid/100000 == user);
        require(uid%100000 >= 10000 && uid%100000 <= 19999);
    }
    public static void logicalBounds(int l,int t,int r,int b,int width,int height) {
        bounds(l,t,r,b);
        require(width>0 && height>0 && width<=4096 && height<=4096);
        require(r<=width && b<=height);
    }
    public static void freshness(long captured, long now) {
        require(captured >= 0 && now >= captured && now-captured <= 15000);
    }
    public static boolean focusLine(String line, int user) {
        return line.matches("\\s*mCurrentFocus=Window\\{[0-9a-fA-F]+ u" + user
            + " com\\.android\\.virtualization\\.terminal/(?:\\.new2\\.ui\\.MainActivity|com\\.android\\.virtualization\\.terminal\\.new2\\.ui\\.MainActivity)\\}");
    }
    /** A 4x4 grid within the interior half of each quadrant: no edges/title/borders. */
    public static int coordinate(int extent, int half, int slot) {
        require(extent >= 32 && extent <= 4096 && half >= 0 && half <= 1 && slot >= 0 && slot < 4);
        int start = half == 0 ? 0 : extent/2;
        int size = half == 0 ? extent/2 : extent-extent/2;
        return start + size*(5+2*slot)/16;
    }
    public static int maxError(int argb, int quadrant) {
        require(quadrant >= 0 && quadrant < 4);
        int[] c = COLORS[quadrant];
        return Math.max(Math.abs(((argb>>16)&255)-c[0]),
            Math.max(Math.abs(((argb>>8)&255)-c[1]),Math.abs((argb&255)-c[2])));
    }
    public static boolean matches(int argb, int quadrant) {
        return (argb>>>24) == 255 && maxError(argb,quadrant) <= TOLERANCE;
    }
    public interface Rows { void read(int y, int[] destination); }
    public enum LocateFailure { PALETTE, SCALE, EDGES, BORDER, INTERIOR }
    /** Only fixed-palette aggregates; no sampled colors or arbitrary screen data. */
    public static final class LocatorRefused extends IllegalArgumentException {
        private final LocateFailure stage;
        private final int[] counts;
        private final int left,top,right,bottom;
        private LocatorRefused(LocateFailure s,int[] c,int l,int t,int r,int b) {
            super("owned pattern locator refused");
            stage=s;counts=c.clone();
            boolean found=r>=l && b>=t;
            left=found?l:-1;top=found?t:-1;right=found?r+1:-1;bottom=found?b+1:-1;
        }
        public String diagnosticJson() {
            return "{\"stage\":\""+stage.name()+"\",\"known_palette_only\":true,\"counts\":["
                +counts[0]+","+counts[1]+","+counts[2]+","+counts[3]
                +"],\"palette_bounds\":["+left+","+top+","+right+","+bottom+"]}";
        }
    }
    private static void located(boolean ok,LocateFailure s,int[] c,int l,int t,int r,int b) {
        if(!ok)throw new LocatorRefused(s,c,l,t,r,b);
    }
    public static final class Located {
        public final int left,top,right,bottom,scaleEighths,palettePixels,borderPixels;
        Located(int l,int t,int r,int b,int s,int p,int border) {
            left=l;top=t;right=r;bottom=b;scaleEighths=s;palettePixels=p;borderPixels=border;
        }
    }
    private static boolean border(int color) {
        return (color>>>24)==255 && Math.abs(((color>>16)&255)-11)<=8
            && Math.abs(((color>>8)&255)-13)<=8 && Math.abs((color&255)-17)<=8;
    }
    /** Locate ONLY the new 640x480 fixture with its 8px border; uniform eighth-step scale.
     * All other pixels are discarded. Any unrelated matching palette pixel can make
     * this deliberately conservative locator refuse; it cannot expand capture scope.
     */
    public static Located locate(int width,int height,Rows rows) {
        bounds(0,0,width,height);
        int[] row=new int[width], counts=new int[4];
        int l=width,t=height,r=-1,b=-1;
        for(int y=0;y<height;y++) {
            rows.read(y,row);
            for(int x=0;x<width;x++) for(int q=0;q<4;q++) if(matches(row[x],q)) {
                counts[q]++;l=Math.min(l,x);t=Math.min(t,y);r=Math.max(r,x);b=Math.max(b,y);break;
            }
        }
        for(int n:counts)located(n>0,LocateFailure.PALETTE,counts,l,t,r,b);
        int innerW=r-l+1,innerH=b-t+1;
        located(innerW%78==0 && innerH%58==0,LocateFailure.SCALE,counts,l,t,r,b);
        int eighths=innerW/78;
        located(eighths>=4 && eighths<=32 && innerH/58==eighths,LocateFailure.SCALE,counts,l,t,r,b);
        int left=l-eighths,top=t-eighths,right=r+1+eighths,bottom=b+1+eighths;
        // Cropped/edge-touching fixtures cannot establish complete outer-border coverage.
        located(left>0 && top>0 && right<width && bottom<height,LocateFailure.EDGES,counts,l,t,r,b);
        int borderCount=0;
        for(int y=top;y<bottom;y++) {
            rows.read(y,row);
            for(int x=left;x<right;x++) {
                int sx=(x-left)*8/eighths,sy=(y-top)*8/eighths;
                if(sx<8 || sx>=632 || sy<8 || sy>=472) {
                    located(border(row[x]),LocateFailure.BORDER,counts,l,t,r,b);borderCount++;
                } else located(matches(row[x],(sy<240?0:2)+(sx<320?0:1)),LocateFailure.INTERIOR,counts,l,t,r,b);
            }
        }
        return new Located(left,top,right,bottom,eighths,counts[0]+counts[1]+counts[2]+counts[3],borderCount);
    }
}
