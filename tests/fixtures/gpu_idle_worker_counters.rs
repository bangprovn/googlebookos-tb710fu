// Copyright 2018 The ChromiumOS Authors (extracted enum attribution).
// Full pinned source redistribution notice follows:
// Copyright 2017 The ChromiumOS Authors
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::cell::RefCell;
thread_local! {static CAPTURE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };}
macro_rules! info {($($arg:tt)*) => { CAPTURE.with(|lines| lines.borrow_mut().push(format!($($arg)*))) };}
// ACTUAL_WORKER_TOKEN
// ACTUAL_GPU_IDLE_COUNTERS
fn main() {
    let scenario=std::env::args().nth(1).expect("host scenario");
    GB_GPU_IDLE_RECORDS.store(0,Ordering::Relaxed);
    match scenario.as_str() {
        "tokens" => {
            for selection in [None,Some(""),Some("1"),Some("worker-counters-v1 "),Some(" worker-counters-v1"),Some("worker-counters-v1-extra")] {
                assert!(GpuIdleCounters::new(selection).is_none());
            }
            assert!(GpuIdleCounters::new(Some("worker-counters-v1")).is_some());
            gpu_idle_checkpoint(&mut None,Some(Instant::now()),true);
            CAPTURE.with(|lines|assert!(lines.borrow().is_empty()));
            println!("HOST_PASS");
        }
        "events" => {
            let mut trace=GpuIdleCounters::new(Some("worker-counters-v1")).unwrap();
            trace.wait_completed(Duration::from_nanos(100_000),false);
            trace.wait_completed(Duration::from_secs(1),true);
            for token in [WorkerToken::CtrlQueue,WorkerToken::CursorQueue,WorkerToken::Display,WorkerToken::GpuControl,WorkerToken::ResourceBridge{index:usize::MAX},WorkerToken::VirtioGpuPoll,WorkerToken::FlipFence,WorkerToken::Sleep,WorkerToken::Kill] {
                if let WorkerToken::ResourceBridge{index}=token {assert_eq!(index,usize::MAX);}
                trace.readable_event(token);
            }
            trace.readable_event(WorkerToken::ResourceBridge{index:0});
            trace.queue_progress(false);trace.queue_progress(true);
            trace.flip_sweep(3,1);trace.flip_sweep(1,2);
            println!("{}",trace.record(Duration::from_secs(5),Duration::from_millis(2),false).unwrap());
        }
        "time_and_budget" => {
            let mut trace=GpuIdleCounters::new(Some("worker-counters-v1")).unwrap();
            assert!(trace.record(Duration::from_nanos(4_999_999_999),Duration::ZERO,false).is_none());
            assert!(trace.record(Duration::from_secs(5),Duration::ZERO,false).is_some());
            assert!(trace.record(Duration::from_nanos(9_999_999_999),Duration::ZERO,false).is_none());
            assert!(trace.record(Duration::from_secs(10),Duration::ZERO,false).is_some());
            assert!(trace.record(Duration::from_secs(9),Duration::ZERO,false).is_none());
            for i in 3..=16 {
                let line=trace.record(Duration::from_secs(i*5),Duration::ZERO,false).unwrap();
                assert!(line.len()<=2048);
            }
            assert!(trace.record(Duration::MAX,Duration::MAX,true).is_none());
            assert_eq!(GB_GPU_IDLE_RECORDS.load(Ordering::Relaxed),16);
            // Recreating a worker cannot reset the process-wide cap.
            assert!(GpuIdleCounters::new(Some("worker-counters-v1")).is_none());
            let mut finished=Some(trace);
            gpu_idle_checkpoint(&mut finished,Some(Instant::now()),true);
            assert!(finished.is_none());
            println!("HOST_PASS");
        }
        "saturation" => {
            let mut trace=GpuIdleCounters::new(Some("worker-counters-v1")).unwrap();
            trace.waits=u64::MAX;trace.empty_waits=u64::MAX;trace.quick_waits=u64::MAX;
            trace.wait_ns=u64::MAX;trace.work_ns=u64::MAX;trace.readable=[u64::MAX;10];
            trace.ctrl_progress_batches=u64::MAX;trace.cursor_progress_batches=u64::MAX;
            trace.flip_retired=u64::MAX;
            trace.wait_completed(Duration::ZERO,true);trace.wait_completed(Duration::MAX,true);
            trace.readable_event(WorkerToken::CtrlQueue);trace.queue_progress(false);trace.queue_progress(true);
            trace.flip_sweep(usize::MAX,0);
            let line=trace.record(Duration::MAX,Duration::MAX,true).unwrap();assert!(line.len()<=2048);println!("{line}");
            GB_GPU_IDLE_RECORDS.store(u32::MAX,Ordering::Relaxed);
            assert!(trace.record(Duration::MAX,Duration::ZERO,true).is_none());
            assert_eq!(GB_GPU_IDLE_RECORDS.load(Ordering::Relaxed),u32::MAX);
        }
        "concurrent_budget" => {
            let lines=std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let threads:Vec<_>=(0..8).map(|_|{
                let lines=lines.clone();std::thread::spawn(move||{
                    if let Some(mut trace)=GpuIdleCounters::new(Some("worker-counters-v1")) {
                        for _ in 0..4 {if let Some(line)=trace.record(Duration::ZERO,Duration::ZERO,true){assert!(line.len()<=2048);lines.lock().unwrap().push(line);}}
                    }
                })
            }).collect();
            for worker in threads {worker.join().unwrap();}
            let lines=lines.lock().unwrap();assert_eq!(lines.len(),16);
            for line in lines.iter(){println!("{line}");}
        }
        "checkpoint" => {
            let mut trace=GpuIdleCounters::new(Some("worker-counters-v1"));
            gpu_idle_checkpoint(&mut trace,Some(Instant::now()),true);
            CAPTURE.with(|lines|{let lines=lines.borrow();assert_eq!(lines.len(),1);assert!(lines[0].len()<=2048);println!("{}",lines[0]);});
            gpu_idle_checkpoint(&mut trace,None,true);
            CAPTURE.with(|lines|assert_eq!(lines.borrow().len(),1));
        }
        _=>panic!("unknown host scenario"),
    }
}
