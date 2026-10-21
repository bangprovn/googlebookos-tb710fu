#!/usr/bin/env python3
"""Host-only pure pattern regression; no Android/device or network execution.

Uses the existing pinned build request's JDK. Compiles only owned plain Java.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("build_request", type=Path)
a = parser.parse_args()
tools = json.loads(a.build_request.read_text())["java"]["tools"]
for name in ("java", "javac"):
    p = Path(tools[name]["path"])
    assert p.is_file() and not p.is_symlink()
    with p.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == tools[name]["sha256"]
with tempfile.TemporaryDirectory(prefix="gb-owned-display-pattern-") as directory:
    base = Path(directory)
    harness = base / "DisplayPatternSelfTest.java"
    harness.write_text('''package org.googlebook.port.hardwareprobe;
public final class DisplayPatternSelfTest {
 static void check(boolean ok){if(!ok)throw new AssertionError("fixed pattern regression");}
 public static void main(String[]args){
  int[][] colors={{0xffff0000,0xff00ff00,0xff0000ff,0xffffffff},
                  {0xff00ff00,0xff0000ff,0xffffffff,0xffff0000},
                  {0xff0000ff,0xffffffff,0xffff0000,0xff00ff00}};
  check(DisplayPattern.sampleCoordinate(0)==8 && DisplayPattern.sampleCoordinate(15)==248);
  for(int phase=0;phase<3;phase++){
   int matches=0,stale=0;
   for(int y=0;y<16;y++)for(int x=0;x<16;x++){
    int px=DisplayPattern.sampleCoordinate(x),py=DisplayPattern.sampleCoordinate(y);
    int q=(x>=8?1:0)+(y>=8?2:0),expected=colors[phase][q];
    check(DisplayPattern.expected(phase,px,py)==expected);
    if(DisplayPattern.matches(expected,DisplayPattern.expected(phase,px,py)))matches++;
    if(DisplayPattern.matches(colors[(phase+2)%3][q],expected))stale++;
   }
   check(matches==256 && stale==0);
  }
  check(DisplayPattern.matches(0xff040404,0xff000000));
  check(!DisplayPattern.matches(0xff050000,0xff000000));
  check(!DisplayPattern.matches(0xfa000000,0xff000000));
  for(int value:new int[]{-1,16}){boolean refused=false;try{DisplayPattern.sampleCoordinate(value);}catch(IllegalArgumentException e){refused=true;}check(refused);}
  System.out.println("PASS: fixed quadrant/phase geometry,768 samples,stale phase rejection,tolerance and bounds");
 }
}''')
    env = {k:v for k,v in os.environ.items() if k not in
           ("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")}
    subprocess.run([tools["javac"]["path"], "-d", str(base), str(harness),
                    str(root/"crates/gb-framework/src/hardware_probe/DisplayPattern.java")],
                   check=True, timeout=30, env=env)
    subprocess.run([tools["java"]["path"], "-cp", str(base),
                    "org.googlebook.port.hardwareprobe.DisplayPatternSelfTest"],
                   check=True, timeout=10, env=env)
