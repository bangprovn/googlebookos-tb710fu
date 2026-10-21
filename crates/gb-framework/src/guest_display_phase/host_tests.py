#!/usr/bin/env python3
"""Synthetic owned-pattern policy; no device, Android images, or user data."""
from pathlib import Path
import hashlib,json,os,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parent
HARNESS=r'''
import org.googlebook.port.guestdisplayphase.PhasePatternContract;
public class Harness {
 static void ok(boolean x){if(!x)throw new AssertionError();}
 interface Action{void run();}static void refused(Action a){try{a.run();}catch(IllegalArgumentException expected){return;}throw new AssertionError("accepted");}
 static int color(int q,int phase){int[] c=PhasePatternContract.COLORS[(q+phase)%4];return 0xff000000|c[0]<<16|c[1]<<8|c[2];}
 static class Fixture implements PhasePatternContract.Rows {
  int phase,expectedPhase,eighths=8,left=80,top=60,width=800,height=600;String mode="valid";
  int w(){return phase==1?480:640;}int h(){return phase==1?360:480;}
  public void read(int y,int[] row){for(int x=0;x<row.length;x++){
   row[x]=0xff555555;boolean inside=x>=left&&y>=top&&x<left+w()*eighths/8&&y<top+h()*eighths/8;
   int sx=(x-left)*8/eighths,sy=(y-top)*8/eighths;
   if(inside){if(sx<8||sx>=w()-8||sy<8||sy>=h()-8)row[x]=0xff0b0d11;else row[x]=color((sy<h()/2?0:2)+(sx<w()/2?0:1),phase);}
   if(mode.equals("overlay")&&inside&&y>=top+100&&y<top+200)row[x]=0xff555555;
   if(mode.equals("no-border")&&inside&&(sx<8||sx>=w()-8||sy<8||sy>=h()-8))row[x]=0xff555555;
   if(mode.equals("foreign-palette")&&x==4&&y==4)row[x]=color(0,0);
   if(mode.equals("corrupted")&&x==left+50&&y==top+50)row[x]=0xff555555;
   if(mode.equals("blank"))row[x]=0xff555555;
  }}
  PhasePatternContract.Located locate(){int[] e=PhasePatternContract.extent(expectedPhase);return PhasePatternContract.locate(width,height,expectedPhase,e[0],e[1],this);}
 }
 public static void main(String[]a){String test=a[0];Fixture f=new Fixture();
  if(test.startsWith("phase")){int p=Integer.parseInt(test.substring(5));f.phase=p;f.expectedPhase=p;var r=f.locate();ok(r.right-r.left==f.w()&&r.bottom-r.top==f.h());int count=(f.w()/2-8)*(f.h()/2-8);for(int n:r.paletteCounts)ok(n==count);ok(r.palettePixels==4*count);ok(r.borderPixels==f.w()*f.h()-4*count);}
  else if(test.equals("stale0-as2")){f.expectedPhase=2;refused(()->f.locate());}
  else if(test.equals("stale0-as1")){f.expectedPhase=1;refused(()->f.locate());}
  else if(test.startsWith("scale")){f.eighths=Integer.parseInt(test.substring(5));f.width=160+640*f.eighths/8;f.height=120+480*f.eighths/8;var r=f.locate();ok(r.scaleEighths==f.eighths&&r.right-r.left==640*f.eighths/8);}
  else if(test.equals("shrink-odd-scale")){f.phase=1;f.expectedPhase=1;f.eighths=7;var r=f.locate();ok(r.scaleEighths==7);ok(r.paletteCounts[1]==203*151&&r.paletteCounts[2]==203*151&&r.paletteCounts[3]==203*150&&r.paletteCounts[0]==203*150);}
  else if(test.equals("edge")){f.left=0;refused(()->f.locate());}
  else if(test.equals("clipped")){f.width=700;refused(()->f.locate());}
  else if(test.equals("overlay")||test.equals("blank")||test.equals("no-border")||test.equals("foreign-palette")||test.equals("corrupted")){f.mode=test;refused(()->f.locate());}
  else if(test.equals("bounds")){PhasePatternContract.bounds(0,0,4096,2048);refused(()->PhasePatternContract.bounds(0,0,4096,2049));refused(()->PhasePatternContract.bounds(0,0,4097,32));refused(()->PhasePatternContract.logicalBounds(0,0,640,480,639,480));}
  else if(test.equals("invalid-phase-extent")){refused(()->PhasePatternContract.extent(-1));refused(()->PhasePatternContract.extent(3));refused(()->PhasePatternContract.frame(1,640,480));refused(()->PhasePatternContract.frame(2,480,360));}
  else if(test.equals("freshness-owner-focus")){PhasePatternContract.freshness(100,15100);refused(()->PhasePatternContract.freshness(100,15101));refused(()->PhasePatternContract.freshness(101,100));PhasePatternContract.owner(11,1110248);refused(()->PhasePatternContract.owner(0,1110248));ok(PhasePatternContract.focusLine("  mCurrentFocus=Window{abc u11 com.android.virtualization.terminal/.new2.ui.MainActivity}",11));ok(!PhasePatternContract.focusLine("prefix mCurrentFocus=Window{abc u11 com.android.virtualization.terminal/.new2.ui.MainActivity}",11));}
  else if(test.equals("colors")){for(int p=0;p<3;p++)for(int q=0;q<4;q++){int c=color(q,p);ok(PhasePatternContract.matches(c,q,p));ok(!PhasePatternContract.matches(c,q,(p+1)%3));ok(PhasePatternContract.maxError(c,q,p)==0);}}
  else if(test.startsWith("digest")){System.out.print(PhasePatternContract.contractDigest(Integer.parseInt(test.substring(6))));return;}
  else throw new AssertionError("unknown scenario");System.out.println("PASS "+test);
 }
}
'''
class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix="gb-phase-crop-policy-");cls.out=Path(cls.tmp.name)
        h=cls.out/'Harness.java';h.write_text(HARNESS)
        subprocess.run(['javac','-proc:none','-d',str(cls.out),str(ROOT/'PhasePatternContract.java'),str(h)],check=True,capture_output=True,timeout=20)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_owned_phase_policy(self):
        for name in ['phase0','phase1','phase2','stale0-as2','stale0-as1','scale4','scale7','scale16','scale20','scale32','shrink-odd-scale','edge','clipped','overlay','blank','no-border','foreign-palette','corrupted','bounds','invalid-phase-extent','freshness-owner-focus','colors']:
            with self.subTest(name=name):
                r=subprocess.run(['java','-Xmx128m','-cp',str(self.out),'Harness',name],capture_output=True,text=True,timeout=5)
                self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'PASS '+name+'\n')
    def test_exact_contract_vectors(self):
        for p,(w,h) in enumerate([(640,480),(480,360),(640,480)]):
            raw=f'GB_VULKAN_LIFECYCLE_V1:{p}:{w}:{h}:border=8:palette=19,67,139;203,37,91;47,181,113;211,173,53:rotation={p}'.encode()
            r=subprocess.run(['java','-cp',str(self.out),'Harness','digest'+str(p)],capture_output=True,text=True,check=True,timeout=5)
            self.assertEqual(r.stdout,hashlib.sha256(raw).hexdigest())
    def test_capture_scope(self):
        s=(ROOT/'GuestDisplayPhaseProbe.java').read_text()
        for bad in ['setAccessible','FileOutputStream','compress(','getMessage(','printStackTrace(','android.window.ScreenCapture":"']:
            self.assertNotIn(bad,s)
        self.assertEqual(s.count('request.invoke(wm,0,args,listener)'),1)
        for required in ['argsType.getField("mSourceCrop")','argsType.getField("mUid")','setSecureContentPolicy','setProtectedContentPolicy','PhasePatternContract.frame(patternPhase,width,height)','Thread.sleep(10000)','buffer.getWidth()==r-l','paletteCounts=region.paletteCounts','contractDigest(patternPhase)']:
            self.assertIn(required,s)
        self.assertLess(s.index('int[] display=identity('),s.index('request.invoke(wm,0,args,listener)'))
        self.assertGreater(s.index('int[] after=identity('),s.index('request.invoke(wm,0,args,listener)'))
if __name__=='__main__':unittest.main()
