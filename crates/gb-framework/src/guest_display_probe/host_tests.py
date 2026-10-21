#!/usr/bin/env python3
"""Pure synthetic policy tests; no Android connection, device images or user data."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
HARNESS = r'''
import org.googlebook.port.guestdisplay.PatternContract;
public final class Harness {
 static void check(boolean b){if(!b)throw new AssertionError();}
 interface Action {void run();}
 static void refused(Action a){try{a.run();}catch(IllegalArgumentException expected){return;}throw new AssertionError("accepted");}
 static int color(int q){int[] c=PatternContract.COLORS[q];return 0xff000000|c[0]<<16|c[1]<<8|c[2];}
 static final class Fixture implements PatternContract.Rows {
  int width=800,height=600,left=80,top=60,eighths=8;String mode="valid";
  public void read(int y,int[] row){
   for(int x=0;x<row.length;x++){
    row[x]=0xff555555;int sx=(x-left)*8/eighths,sy=(y-top)*8/eighths;
    boolean inside=x>=left&&y>=top&&x<left+80*eighths&&y<top+60*eighths;
    if(inside){
     if(sx<8||sx>=632||sy<8||sy>=472)row[x]=0xff0b0d11;
     else row[x]=color((sy<240?0:2)+(sx<320?0:1));
    }
    if(mode.equals("no-border")&&inside&&(sx<8||sx>=632||sy<8||sy>=472))row[x]=0xff555555;
    if(mode.equals("partial")&&inside&&sx<200)row[x]=0xff555555;
    if(mode.equals("wrong-quadrant")&&inside&&sx>=8&&sx<320&&sy>=8&&sy<240)row[x]=color(1);
    if(mode.equals("corrupted")&&x==left+50&&y==top+50)row[x]=0xff555555;
    if(mode.equals("foreign-palette")&&x==4&&y==4)row[x]=color(0);
    if(mode.equals("blank"))row[x]=0xff555555;
   }
  }
  PatternContract.Located locate(){return PatternContract.locate(width,height,this);}
 }
 public static void main(String[] a){String test=a[0];Fixture f=new Fixture();
  if(test.equals("valid")){var r=f.locate();check(r.left==80&&r.top==60&&r.right==720&&r.bottom==540&&r.scaleEighths==8);check(r.palettePixels==624*464);check(r.borderPixels==640*480-624*464);}
  else if(test.equals("scale-two")){f.width=1440;f.height=1080;f.eighths=16;var r=f.locate();check(r.scaleEighths==16&&r.palettePixels==624*464*4&&r.borderPixels==(640*480-624*464)*4);}
  else if(test.equals("scale-two-half")){f.width=1800;f.height=1320;f.eighths=20;var r=f.locate();check(r.scaleEighths==20&&r.right-r.left==1600&&r.bottom-r.top==1200);}
  else if(test.equals("edge-touch")){f.left=0;refused(()->f.locate());}
  else if(test.equals("clipped")){f.width=700;refused(()->f.locate());}
  else if(test.equals("blank")||test.equals("no-border")||test.equals("partial")||test.equals("wrong-quadrant")||test.equals("foreign-palette")||test.equals("corrupted")){f.mode=test;refused(()->f.locate());}
  else if(test.equals("bounds")){PatternContract.bounds(0,0,4096,2048);refused(()->PatternContract.bounds(0,0,4096,2049));refused(()->PatternContract.bounds(0,0,4097,32));refused(()->PatternContract.bounds(-1,0,640,480));refused(()->PatternContract.bounds(8,9,8,20));}
  else if(test.equals("logical-bounds")){PatternContract.logicalBounds(0,190,3200,1860,3200,2000);PatternContract.logicalBounds(0,0,640,480,640,480);}
  else if(test.equals("logical-outside")){refused(()->PatternContract.logicalBounds(1,0,641,480,640,480));refused(()->PatternContract.logicalBounds(0,1,640,481,640,480));}
  else if(test.equals("logical-invalid")){for(int n:new int[]{-1,0,4097}){final int v=n;refused(()->PatternContract.logicalBounds(0,0,640,480,v,480));refused(()->PatternContract.logicalBounds(0,0,640,480,640,v));}}
  else if(test.equals("owner")){PatternContract.owner(11,1110248);refused(()->PatternContract.owner(10,1110248));refused(()->PatternContract.owner(11,1102000));refused(()->PatternContract.owner(215,21510000));}
  else if(test.equals("stale")){PatternContract.freshness(100,15100);refused(()->PatternContract.freshness(100,15101));refused(()->PatternContract.freshness(101,100));refused(()->PatternContract.freshness(-1,100));}
  else if(test.equals("focus")){check(PatternContract.focusLine("  mCurrentFocus=Window{abc u11 com.android.virtualization.terminal/.new2.ui.MainActivity}",11));check(!PatternContract.focusLine("mCurrentFocus=Window{abc u0 com.android.virtualization.terminal/.new2.ui.MainActivity}",11));check(!PatternContract.focusLine("mCurrentFocus=Window{abc u11 evil/com.android.virtualization.terminal.new2.ui.MainActivity}",11));check(!PatternContract.focusLine("prefix mCurrentFocus=Window{abc u11 com.android.virtualization.terminal/.new2.ui.MainActivity}",11));}
  else if(test.equals("colors")){int c=color(0);check(PatternContract.matches(c,0));check(PatternContract.matches(c+8,0));check(!PatternContract.matches(c+9,0));check(!PatternContract.matches(c&0xffffff,0));for(int q=1;q<4;q++)check(!PatternContract.matches(c,q));}
  else if(test.equals("sampling")){for(int e:new int[]{32,640,1024,4096})for(int h=0;h<2;h++)for(int s=0;s<4;s++){int c=PatternContract.coordinate(e,h,s);check(c>h*e/2&&c<(h+1)*e/2);}refused(()->PatternContract.coordinate(0,0,0));}
  else if(test.equals("diagnostics")){
   for(String mode:new String[]{"blank","no-border","corrupted","foreign-palette","edge-touch"}){
    Fixture diagnostic=new Fixture();diagnostic.mode=mode;if(mode.equals("edge-touch"))diagnostic.left=0;
    try{diagnostic.locate();throw new AssertionError("accepted");}
    catch(PatternContract.LocatorRefused e){
     String d=e.diagnosticJson();
     String stage=mode.equals("blank")?"PALETTE":mode.equals("no-border")?"BORDER":mode.equals("corrupted")?"INTERIOR":mode.equals("foreign-palette")?"SCALE":"EDGES";
     check(d.startsWith("{\"stage\":\""+stage+"\",\"known_palette_only\":true,"));
     if(mode.equals("blank"))check(d.equals("{\"stage\":\"PALETTE\",\"known_palette_only\":true,\"counts\":[0,0,0,0],\"palette_bounds\":[-1,-1,-1,-1]}"));
     if(mode.equals("corrupted"))check(d.equals("{\"stage\":\"INTERIOR\",\"known_palette_only\":true,\"counts\":[72383,72384,72384,72384],\"palette_bounds\":[88,68,712,532]}"));
    }
   }
  }
  else throw new AssertionError("unknown scenario");
  System.out.println("PASS "+test);
 }
}
'''


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="gb-crop-policy-")
        cls.root = pathlib.Path(cls.tmp.name)
        harness = cls.root / "Harness.java"
        harness.write_text(HARNESS)
        result = subprocess.run(["javac", "-proc:none", "-d", str(cls.root),
                                 str(ROOT / "PatternContract.java"), str(harness)],
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_synthetic_policy(self):
        scenarios = ["valid", "scale-two", "scale-two-half", "edge-touch", "clipped", "blank", "no-border", "partial",
                     "wrong-quadrant", "foreign-palette", "corrupted", "bounds", "owner", "stale",
                     "focus", "colors", "sampling", "logical-bounds", "logical-outside", "logical-invalid", "diagnostics"]
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                r = subprocess.run(["java", "-Xmx128m", "-cp", str(self.root), "Harness", scenario],
                                   capture_output=True, text=True, timeout=5)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout, f"PASS {scenario}\n")

    def test_capture_source_scope(self):
        source = (ROOT / "GuestDisplayProbe.java").read_text()
        self.assertNotIn("setAccessible", source)
        self.assertNotIn("compress(", source)
        self.assertNotIn("FileOutputStream", source)
        self.assertNotIn("screencap", source)
        self.assertEqual(source.count("request.invoke(wm,0,args,listener)"), 1)
        self.assertIn('argsType.getField("mSourceCrop")', source)
        self.assertIn('argsType.getField("mUid")', source)
        self.assertLess(source.index('int[] display=identity('), source.index('request.invoke(wm,0,args,listener)'))
        self.assertGreater(source.index('int[] after=identity('), source.index('request.invoke(wm,0,args,listener)'))
        self.assertIn('Class.forName("android.hardware.display.DisplayManagerGlobal")', source)
        self.assertIn('"getDisplayInfo",new Class<?>[]{int.class},0', source)
        self.assertIn('infoType.getField("logicalWidth").getInt(info)', source)
        self.assertIn('infoType.getField("logicalHeight").getInt(info)', source)
        self.assertIn('PatternContract.logicalBounds(l,t,r,b,width,height)', source)
        self.assertIn('check(after[0]==displayWidth && after[1]==displayHeight)', source)
        # Both explicit API profiles retain cropping, UID and redaction. Contract
        # mode exits before the only capture call; diagnostics expose no messages.
        self.assertIn('"android.window.ScreenCaptureInternal":"android.window.ScreenCapture"', source)
        self.assertIn('params.getField("SECURE_CONTENT_POLICY_REDACT").getInt(null)==0', source)
        self.assertIn('params.getField("PROTECTED_CONTENT_POLICY_REDACT").getInt(null)==0', source)
        self.assertIn('argsType.getField("mSecureContentPolicy").getInt(args)==0', source)
        self.assertIn('argsType.getField("mProtectedContentPolicy").getInt(args)==0', source)
        contract = source.index('if (contractOnly) {')
        self.assertLess(contract, source.index('request.invoke(wm,0,args,listener)'))
        self.assertIn('return;', source[contract:source.index('phase = "capture";', contract)])
        self.assertNotIn('getMessage(', source)
        self.assertNotIn('printStackTrace(', source)
        self.assertIn('if(shot instanceof AutoCloseable) ((AutoCloseable)shot).close()', source)


if __name__ == "__main__":
    unittest.main()
