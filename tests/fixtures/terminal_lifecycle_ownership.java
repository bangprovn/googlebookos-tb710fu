// SPDX-License-Identifier: Apache-2.0
// Host-only stand-ins and ownership MODEL. Actual donor methods are inserted
// at test time from pinned inputs; no donor APK code is bundled in this fixture.
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class TerminalLifecycleOwnership {
    enum NativeStatus { NONE, RUNNING, UNKNOWN, STOPPED }
    static void require(boolean value) { if (!value) throw new AssertionError("host lifecycle invariant"); }
    interface VmState {
        final class Ready implements VmState { static final Ready INSTANCE=new Ready(); }
        final class Starting implements VmState { static final Starting INSTANCE=new Starting(); }
        final class Running implements VmState { static final Running INSTANCE=new Running(); }
        final class Stopping implements VmState { static final Stopping INSTANCE=new Stopping(); }
        final class Stopped implements VmState { static final Stopped INSTANCE=new Stopped(); }
        final class Rebooting implements VmState { static final Rebooting INSTANCE=new Rebooting(); }
        final class Error implements VmState { static final Error INSTANCE=new Error(); }
        // ACTUAL_ALIVE_GATE
    }
    static final class Flow<T> {
        T value; Flow(T value) {this.value=value;} T getValue(){return value;}
    }
    static final class LoggingMutableStateFlow {
        final Flow<VmState> originalFlow=new Flow<>(VmState.Ready.INSTANCE);
        void setValue(VmState value){originalFlow.value=value;}
    }
    static class InstallState {static final class Installing extends InstallState {}}
    static final class Installer {static final Flow<Object> installState=new Flow<>(new InstallState());}
    static final class Intrinsics {
        static boolean areEqual(Object a,Object b){return Objects.equals(a,b);}
        static void throwUninitializedPropertyAccessException(String ignored){throw new AssertionError("host initialization");}
    }
    static final class SharedPreferences {String getString(String ignored,String fallback){return fallback;}}
    static final class Intent {Intent(Context context,Class<?> type){require(context!=null&&type==VmService.class);}}
    static final class Context {
        SharedPreferences getSharedPreferences(String ignored,int mode){return new SharedPreferences();}
        void startForegroundService(Intent ignored){world.serviceQueued=true;world.note("actual_service_requested");}
    }
    static final class C01011 {C01011(String config,String console,SharedPreferences prefs,Object continuation){}}
    static final class BuildersKt__Builders_commonKt {
        static void launch$default(Object scope,Object context,Object start,C01011 task,int flags,Object marker){world.workerQueued=true;world.note("actual_worker_enqueued");}
    }
    static final class VmController {
        static final VmController INSTANCE=new VmController();
        static final LoggingMutableStateFlow _vmState=new LoggingMutableStateFlow();
        static final Context context=new Context();
        static final Object repositoryScope=new Object();
        static Object virtualMachine;
        Flow<VmState> getVmState(){return _vmState.originalFlow;}
        // ACTUAL_START
        // ACTUAL_RESET
    }
    static final class VmService {
        void stopSelf(){world.service=false;world.note("actual_gate_stopped_service");}
        // ACTUAL_SERVICE_GATE
    }
    // Actual donor framework methods below use explicit native/Binder stand-ins.
    static final class RemoteException extends Exception {
        private static final long serialVersionUID=1L;
        RuntimeException rethrowAsRuntimeException(){return new IllegalStateException("modeled binder failure");}
    }
    static final class ServiceSpecificException extends RuntimeException {private static final long serialVersionUID=1L;}
    static final class VirtualMachineException extends Exception {
        private static final long serialVersionUID=1L;
        VirtualMachineException(String ignored,int code){}
        VirtualMachineException(Throwable cause){super(cause);}
    }
    interface IVirtualMachine {int getState() throws RemoteException;void stop() throws RemoteException;}
    static final class RootPath {boolean exists(){return true;}}
    static final class FakeNative implements IVirtualMachine {
        boolean live=true,statusFailure,stopFailure;
        int stopCalls;
        public int getState() throws RemoteException {if(statusFailure)throw new RemoteException();return live?1:5;}
        public void stop() throws RemoteException {stopCalls++;if(stopFailure)throw new RemoteException();live=false;}
    }
    static final class DonorFrameworkVm {
        final Object mLock=new Object();
        final RootPath mVmRootPath=new RootPath();
        boolean mWasDeleted;
        IVirtualMachine mVirtualMachine;
        final FakeNative cleanerOwner;
        boolean cleanerDone;
        DonorFrameworkVm(FakeNative owner){mVirtualMachine=owner;cleanerOwner=owner;}
        void dropVm(){
            mVirtualMachine=null;
            // Source-constrained dropVm/DeathAction stand-in: clean runs once,
            // attempts captured native stop, and suppresses a remote failure.
            if(!cleanerDone){cleanerDone=true;try{cleanerOwner.stop();}catch(RemoteException ignored){}}
        }
        // ACTUAL_FRAMEWORK_STATUS
        // ACTUAL_FRAMEWORK_STATE_TO_STATUS
        // ACTUAL_FRAMEWORK_STOP
    }
    static final class Trace {
        final List<String> records=new ArrayList<>();
        String lastRecord="null";
        int suppressed;
        void add(String event,String state,NativeStatus nativeStatus,boolean foreground,boolean pending,boolean blocked,int stops){
            String record="{\"event\":\""+event+"\",\"controller_state\":\""+state+"\",\"native_status\":\""+nativeStatus+"\",\"foreground\":"+foreground+",\"pending_start\":"+pending+",\"blocked\":"+blocked+",\"stop_requests\":"+stops+"}";
            lastRecord=record;
            if(records.size()>=32){suppressed=(int)Math.min(Integer.MAX_VALUE,(long)suppressed+1);return;}
            records.add(record);
        }
    }
    static String state(VmState value){return value.getClass().getSimpleName();}
    static SourceWorld world;
    static final class SourceWorld {
        final Trace trace=new Trace();
        NativeStatus nativeStatus=NativeStatus.NONE;
        boolean serviceQueued,workerQueued,service;
        int stops;
        SourceWorld(){VmController._vmState.setValue(VmState.Ready.INSTANCE);VmController.virtualMachine=null;}
        void note(String event){trace.add(event,state(VmController._vmState.originalFlow.getValue()),nativeStatus,service,workerQueued,false,stops);}
        void createServiceAndInitialCollector(){require(serviceQueued);service=true;note("modeled_service_foreground");new VmService().checkStopSelf();}
        void workerCompletes(){
            require(workerQueued);workerQueued=false;
            // Controlled stand-in for the separately scheduled actual coroutine.
            VmController._vmState.setValue(VmState.Starting.INSTANCE);note("modeled_worker_starting");
            VmController.virtualMachine=new Object();nativeStatus=NativeStatus.RUNNING;
            VmController._vmState.setValue(VmState.Running.INSTANCE);note("modeled_worker_running");
        }
        void modeledBridgeError(){
            // Source-constrained transition: actual reconstructed handleVmError
            // cannot compile, but publishes Error and only stops GuestAgentController.
            VmController._vmState.setValue(VmState.Error.INSTANCE);note("modeled_matching_bridge_error");
        }
    }

    // Separate repair CONTRACT MODEL, not donor production implementation.
    static final class LeaseModel {
        final Trace trace=new Trace();
        VmState ui=VmState.Ready.INSTANCE;
        NativeStatus nativeStatus=NativeStatus.NONE;
        boolean pending,owned,foreground,blocked,stopWanted;
        int generation,stops;
        void note(String event){trace.add(event,state(ui),nativeStatus,foreground,pending,blocked,stops);}
        boolean requestStart(){
            if(pending||owned||blocked||generation>=64){note("model_start_refused");return false;}
            generation++;pending=true;stopWanted=false;stops=0;nativeStatus=NativeStatus.NONE;
            ui=VmState.Starting.INSTANCE;note("model_claim_before_service_exposure");return true;
        }
        void foregroundAcknowledged(int callbackGeneration,boolean accepted){
            if(callbackGeneration!=generation||!pending||owned){note("model_stale_foreground_ack_ignored");return;}
            if(!accepted){pending=false;foreground=false;ui=VmState.Error.INSTANCE;note("model_foreground_denied_no_native_creation");return;}
            foreground=true;note("model_foreground_acknowledged");
        }
        boolean workerCreated(int callbackGeneration){
            if(callbackGeneration!=generation||!pending||!foreground){note("model_native_creation_not_admitted");return false;}
            pending=false;owned=true;nativeStatus=NativeStatus.RUNNING;
            if(stopWanted){ui=VmState.Stopping.INSTANCE;requestStopOnce();}
            else ui=VmState.Running.INSTANCE;
            note("model_native_owned");return true;
        }
        void pendingSettledWithoutNative(int callbackGeneration){
            if(callbackGeneration!=generation||!pending)return;
            pending=false;releaseOnlyIfConfirmed();note("model_pending_settled_without_native");
        }
        void recoverableError(int callbackGeneration){
            if(callbackGeneration!=generation||!owned)return;
            ui=VmState.Error.INSTANCE;note("model_error_keeps_real_ownership");
        }
        void fatalError(){
            stopWanted=true;ui=VmState.Stopping.INSTANCE;
            if(owned)requestStopOnce();
            note("model_fatal_stop_requested");
        }
        void requestStopOnce(){if(stops==0)stops=1;}
        void statusObserved(int callbackGeneration,NativeStatus status){
            if(callbackGeneration!=generation||!owned){note("model_stale_or_unowned_status_ignored");return;}
            // Raw reference getStatus may turn a binder failure into STOPPED.
            // Only a separate trusted exact-owner completion can release lease.
            nativeStatus=status==NativeStatus.RUNNING?NativeStatus.RUNNING:NativeStatus.UNKNOWN;
            note(status==NativeStatus.STOPPED?"model_unconfirmed_stopped_is_unknown":
                 status==NativeStatus.UNKNOWN?"model_binder_failure_is_unknown":"model_status_observed");
        }
        void stopConfirmed(int callbackGeneration){
            if(callbackGeneration!=generation||!owned){note("model_stale_stop_confirmation_ignored");return;}
            nativeStatus=NativeStatus.STOPPED;owned=false;releaseOnlyIfConfirmed();note("model_exact_owner_stop_confirmed");
        }
        void stopDeadline(){
            if(pending||owned){blocked=true;note("model_stop_confirmation_missing");}
            // No fabricated forced cleanup, retry loop, STOPPED or ready reset.
        }
        boolean reset(){
            if(pending||owned||blocked){note("model_reset_refused_owned_or_unknown");return false;}
            ui=VmState.Ready.INSTANCE;note("model_reset_safe");return true;
        }
        void releaseOnlyIfConfirmed(){
            if(!pending&&!owned){foreground=false;blocked=false;ui=VmState.Stopped.INSTANCE;note("model_ownership_released");}
        }
        void invariant(){
            require(!owned||foreground);
            require(nativeStatus!=NativeStatus.RUNNING||owned);
            require(stops>=0&&stops<=1);
            require(!pending||ui instanceof VmState.Starting||ui instanceof VmState.Stopping);
        }
    }
    static Trace run(String name){
        if(name.startsWith("source_framework_")){
            Trace trace=new Trace();FakeNative owner=new FakeNative();DonorFrameworkVm vm=new DonorFrameworkVm(owner);
            if(name.equals("source_framework_status_hidden_failure")){
                owner.statusFailure=true;owner.stopFailure=true;require(vm.getStatus()==0&&owner.live&&vm.mVirtualMachine==owner);
                trace.add("actual_donor_status_hidden_remote_failure","NotModeled",NativeStatus.RUNNING,false,false,false,0);
                boolean failed=false;try{vm.stop();}catch(VirtualMachineException error){failed=true;}
                require(failed&&owner.live&&vm.mVirtualMachine==null&&owner.stopCalls==1);
                trace.add("actual_donor_ambiguous_status_stop_drops_binding","NotModeled",NativeStatus.RUNNING,false,false,false,0);
            }else if(name.equals("source_framework_stop_loses_binding")){
                owner.stopFailure=true;boolean failed=false;try{vm.stop();}catch(IllegalStateException error){failed=true;}catch(VirtualMachineException error){throw new AssertionError(error);}
                require(failed&&owner.live&&vm.mVirtualMachine==null&&owner.stopCalls==2);
                trace.add("actual_donor_failed_stop_drops_binding","NotModeled",NativeStatus.RUNNING,false,false,false,1);
            }else if(name.equals("source_framework_stop_success")){
                try{vm.stop();}catch(VirtualMachineException error){throw new AssertionError(error);}
                require(!owner.live&&vm.mVirtualMachine==null);
                trace.add("actual_donor_successful_stop","NotModeled",NativeStatus.STOPPED,false,false,false,1);
            }else throw new AssertionError("unknown framework case");
            return trace;
        }
        if(name.startsWith("source_")){
            world=new SourceWorld();
            if(name.equals("source_running_missing_service")){
                VmController._vmState.setValue(VmState.Running.INSTANCE);VmController.virtualMachine=new Object();world.nativeStatus=NativeStatus.RUNNING;
                VmController.INSTANCE.start(null);require(!world.serviceQueued&&!world.workerQueued&&!world.service);world.note("source_existing_running_does_not_reconcile_service");return world.trace;
            }
            VmController.INSTANCE.start(null);
            if(name.equals("source_ready_race")){
                world.createServiceAndInitialCollector();require(!world.service);world.workerCompletes();require(!world.service&&VmController.virtualMachine!=null);world.note("ready_start_race_counterexample");
            }else if(name.equals("source_worker_first")){
                world.workerCompletes();world.createServiceAndInitialCollector();require(world.service);world.note("source_coverage_present");
            }else if(name.equals("source_late_error_reset")){
                world.workerCompletes();world.createServiceAndInitialCollector();require(world.service);
                Object owner=VmController.virtualMachine;world.modeledBridgeError();new VmService().checkStopSelf();require(!world.service&&VmController.virtualMachine==owner);
                VmController.INSTANCE.reset();require(VmController._vmState.originalFlow.getValue() instanceof VmState.Ready&&VmController.virtualMachine==owner);world.note("late_error_ready_native_alive_counterexample");
            }else throw new AssertionError("unknown source case");
            return world.trace;
        }
        LeaseModel m=new LeaseModel();require(m.requestStart());int first=m.generation;
        if(name.equals("model_foreground_denied")){
            m.foregroundAcknowledged(first,false);require(!m.workerCreated(first));require(!m.owned&&!m.foreground);m.invariant();return m.trace;
        }
        m.foregroundAcknowledged(first,true);
        if(name.equals("model_cancel_pending")){
            m.fatalError();require(m.pending&&m.foreground);m.invariant();require(m.workerCreated(first));require(m.stops==1);m.stopConfirmed(first);require(!m.owned&&!m.foreground);m.invariant();return m.trace;
        }
        if(name.equals("model_pending_failure")){
            m.pendingSettledWithoutNative(first);require(!m.foreground&&!m.pending&&!m.owned);m.invariant();return m.trace;
        }
        require(m.workerCreated(first));m.invariant();
        if(name.equals("model_ready_and_error")){
            m.recoverableError(first);require(!m.reset()&&!m.requestStart());m.statusObserved(first,NativeStatus.UNKNOWN);m.statusObserved(first,NativeStatus.STOPPED);require(m.owned&&m.foreground);m.invariant();
        }else if(name.equals("model_fatal_unknown")){
            m.fatalError();m.statusObserved(first,NativeStatus.UNKNOWN);m.stopDeadline();require(m.blocked&&m.owned&&m.foreground&&m.stops==1);
            for(int i=0;i<100;i++){m.fatalError();require(!m.requestStart()&&!m.reset());m.invariant();}
            require(m.trace.records.size()==32);m.stopConfirmed(first);require(!m.owned&&!m.foreground&&!m.blocked);m.invariant();
        }else if(name.equals("model_stale_callbacks")){
            m.fatalError();m.stopConfirmed(first);require(m.requestStart());
            m.foregroundAcknowledged(first,false);m.foregroundAcknowledged(first,true);
            require(m.pending&&!m.foreground&&!m.owned);m.invariant();
            m.foregroundAcknowledged(m.generation,true);require(m.workerCreated(m.generation));
            m.stopConfirmed(first);m.recoverableError(first);require(m.owned&&m.foreground&&m.ui instanceof VmState.Running);m.invariant();
        }else throw new AssertionError("unknown model case");
        return m.trace;
    }
    public static void main(String[] args){
        require(args.length==1);Trace trace=run(args[0]);
        boolean enabled="owned-state-only-v1".equals(System.getenv("GB_TERMINAL_LIFECYCLE_MODEL_V1"));
        System.out.println("{\"schema_version\":1,\"implementation_kind\":\"host_lifecycle_model\",\"enabled\":"+enabled+",\"runtime_verified\":false,\"production_fix_implemented\":false,\"records\":["+(enabled?String.join(",",trace.records):"")+"],\"records_suppressed\":"+(enabled?trace.suppressed:0)+",\"final_model_state\":"+(enabled?trace.lastRecord:"null")+"}");
    }
}
