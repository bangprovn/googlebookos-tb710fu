import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.builder.*;
import com.android.tools.smali.dexlib2.builder.instruction.*;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.reference.*;
import com.android.tools.smali.dexlib2.immutable.*;
import com.android.tools.smali.dexlib2.immutable.reference.*;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/** Parse firmware DEX as data. Only the pinned manager's Context constructor changes. */
public final class PatchClient {
    static final String MANAGER = "Lvendor/google/libraries/desktop/serviceability/ServiceabilityManager;";
    static final String HELPER = "Lorg/googlebook/port/serviceability/LazyClient;";
    static final String CONTEXT = "Landroid/content/Context;";
    static final String VENDOR = "Lvendor/google/desktop/serviceability/IVendorServiceabilityService;";
    static final String SYSTEM = "Lvendor/google/desktop/serviceability/IServiceabilityService;";
    static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    static DexFile load(String path) throws Exception {
        var container = DexFileFactory.loadDexContainer(new File(path), Opcodes.getDefault());
        var names = container.getDexEntryNames();
        require(names.size() == 1, "exactly one DEX required");
        return container.getEntry(names.get(0)).getDexFile();
    }
    static boolean constructor(Method method) {
        return method.getName().equals("<init>") && method.getParameterTypes().equals(List.of(CONTEXT));
    }
    static String methodKey(Method m) {
        return m.getName() + m.getParameterTypes() + m.getReturnType();
    }
    static void writePreserved(DexFile file, String path, Set<String> originalNames, boolean omitConstructor) throws Exception {
        List<ClassDef> kept = new ArrayList<>();
        for (ClassDef c : file.getClasses()) {
            if (!originalNames.contains(c.getType())) continue;
            List<Method> methods = new ArrayList<>();
            for (Method m : c.getMethods())
                if (!(omitConstructor && c.getType().equals(MANAGER) && constructor(m))) methods.add(m);
            kept.add(new ImmutableClassDef(c.getType(), c.getAccessFlags(), c.getSuperclass(),
                c.getInterfaces(), c.getSourceFile(), c.getAnnotations(), c.getFields(), methods));
        }
        kept.sort(Comparator.comparing(ClassDef::getType));
        DexPool.writeTo(path, new ImmutableDexFile(file.getOpcodes(), kept));
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 3 || args.length == 1, "input.jar helper.dex output.dex, or inspect input.jar");
        DexFile original = load(args[0]);
        ClassDef manager = null;
        for (ClassDef c : original.getClasses()) if (c.getType().equals(MANAGER)) manager = c;
        require(manager != null, "manager class absent");
        Method target = null;
        for (Method m : manager.getMethods()) if (constructor(m)) {
            require(target == null, "ambiguous constructor"); target = m;
        }
        require(target != null && target.getImplementation() != null, "constructor absent");
        if (args.length == 1) {
            System.out.println("registers=" + target.getImplementation().getRegisterCount());
            int i = 0;
            for (Instruction ins : target.getImplementation().getInstructions()) {
                String ref = ins instanceof ReferenceInstruction ? ((ReferenceInstruction)ins).getReference().toString() : "";
                System.out.println(i++ + " " + ins.getOpcode() + " " + ref);
            }
            return;
        }
        int registers = target.getImplementation().getRegisterCount();
        require(registers >= 6 && registers <= 16, "unsupported constructor register layout");
        int thisReg = registers - 2, contextReg = registers - 1;
        var mutable = new MutableMethodImplementation(target.getImplementation());
        int insertion = -1, binds = 0;
        var instructions = mutable.getInstructions();
        for (int i = 0; i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            if (ins instanceof ReferenceInstruction ri && ri.getReference() instanceof FieldReference field
                    && ins.getOpcode() == Opcode.IPUT_OBJECT && field.getDefiningClass().equals(MANAGER)
                    && field.getName().equals("mContext") && field.getType().equals(CONTEXT)) {
                require(insertion == -1, "ambiguous context store");
                var regs = (TwoRegisterInstruction)ins;
                require(regs.getRegisterA() == contextReg && regs.getRegisterB() == thisReg,
                        "unexpected context registers");
                insertion = i + 1;
            }
            if (ins instanceof ReferenceInstruction ri && ri.getReference() instanceof MethodReference ref
                    && ref.getDefiningClass().equals(MANAGER) && ref.getName().equals("bindService")) binds++;
        }
        require(insertion > 0 && binds == 2, "unexpected eager constructor shape");
        // The pinned remainder starts afresh with the vendor callback field load, then constants.
        // v0..v2 must not hold a live original value across this insertion.
        require(instructions.get(insertion).getOpcode() == Opcode.IGET_OBJECT,
                "unsupported insertion liveness boundary");
        var first = (TwoRegisterInstruction)instructions.get(insertion);
        require(first.getRegisterA() == 0 && first.getRegisterB() == thisReg,
                "unsupported first field load registers");
        Label legacy = mutable.newLabelForIndex(insertion);
        List<BuilderInstruction> added = List.of(
            new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, contextReg, 0, 0, 0, 0,
                new ImmutableMethodReference(HELPER, "isTips", List.of(CONTEXT), "Z")),
            new BuilderInstruction11x(Opcode.MOVE_RESULT, 0),
            new BuilderInstruction21t(Opcode.IF_EQZ, 0, legacy),
            new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, contextReg, 0, 0, 0, 0,
                new ImmutableMethodReference(HELPER, "create", List.of(CONTEXT), "[Ljava/lang/Object;")),
            new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
            new BuilderInstruction11n(Opcode.CONST_4, 1, 0),
            new BuilderInstruction23x(Opcode.AGET_OBJECT, 2, 0, 1),
            new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference(VENDOR)),
            new BuilderInstruction22c(Opcode.IPUT_OBJECT, 2, thisReg,
                new ImmutableFieldReference(MANAGER, "mVendorService", VENDOR)),
            new BuilderInstruction11n(Opcode.CONST_4, 1, 1),
            new BuilderInstruction23x(Opcode.AGET_OBJECT, 2, 0, 1),
            new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference(SYSTEM)),
            new BuilderInstruction22c(Opcode.IPUT_OBJECT, 2, thisReg,
                new ImmutableFieldReference(MANAGER, "mService", SYSTEM)),
            new BuilderInstruction10x(Opcode.RETURN_VOID)
        );
        for (int i = 0; i < added.size(); i++) mutable.addInstruction(insertion + i, added.get(i));
        // addInstruction keeps old labels on the inserted instruction. Explicitly move the legacy
        // label back to the original field load, otherwise the false branch would loop.
        legacy.getLocation().getLabels().remove(legacy);
        mutable.getInstructions().get(insertion + added.size()).getLocation().getLabels().add(legacy);
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef c : original.getClasses()) {
            if (!c.getType().equals(MANAGER)) { classes.add(c); continue; }
            List<Method> methods = new ArrayList<>();
            for (Method m : c.getMethods()) {
                if (!constructor(m)) { methods.add(m); continue; }
                methods.add(new ImmutableMethod(m.getDefiningClass(), m.getName(), m.getParameters(),
                    m.getReturnType(), m.getAccessFlags(), m.getAnnotations(), m.getHiddenApiRestrictions(), mutable));
            }
            classes.add(new ImmutableClassDef(c.getType(), c.getAccessFlags(), c.getSuperclass(),
                c.getInterfaces(), c.getSourceFile(), c.getAnnotations(), c.getFields(), methods));
        }
        Set<String> names = new HashSet<>();
        for (ClassDef c : classes) names.add(c.getType());
        int helpers = 0;
        for (ClassDef c : load(args[1]).getClasses()) {
            require(c.getType().startsWith("Lorg/googlebook/port/serviceability/"), "unexpected helper class");
            require(names.add(c.getType()), "class collision"); classes.add(c); helpers++;
        }
        require(helpers >= 4 && helpers <= 12, "helper class budget");
        DexPool.writeTo(args[2], new ImmutableDexFile(original.getOpcodes(), classes));
        DexFile result = load(args[2]);
        Set<String> originalNames = new HashSet<>();
        int unchangedMethods = 0;
        for (ClassDef c : original.getClasses()) {
            originalNames.add(c.getType());
            if (c.getType().equals(MANAGER))
                for (Method m : c.getMethods()) if (!constructor(m)) unchangedMethods++;
        }
        // ClassDef/Method.equals in dexlib compare references, not implementations. Canonicalize
        // ALL original classes minus just this constructor, then compare actual serialized bytes.
        String before = args[2] + ".preserved-before.dex", after = args[2] + ".preserved-after.dex";
        writePreserved(original, before, originalNames, true);
        writePreserved(result, after, originalNames, true);
        require(Arrays.equals(Files.readAllBytes(Path.of(before)), Files.readAllBytes(Path.of(after))),
                "non-constructor code or metadata changed");
        // Validate the real false branch and reverse the insertion, rather than trusting a
        // string/source guard. This also checks original register/try/debug metadata restoration.
        List<ClassDef> reversedClasses = new ArrayList<>();
        for (ClassDef c : result.getClasses()) if (originalNames.contains(c.getType())) {
            if (!c.getType().equals(MANAGER)) { reversedClasses.add(c); continue; }
            List<Method> reversedMethods = new ArrayList<>();
            for (Method m : c.getMethods()) {
                if (!constructor(m)) { reversedMethods.add(m); continue; }
                var reverse = new MutableMethodImplementation(m.getImplementation());
                int skipUnits = 0;
                for (int i = 2; i < added.size(); i++) skipUnits += reverse.getInstructions().get(insertion+i).getCodeUnits();
                Instruction branch = reverse.getInstructions().get(insertion+2);
                require(branch.getOpcode() == Opcode.IF_EQZ && ((OffsetInstruction)branch).getCodeOffset() == skipUnits,
                        "legacy branch does not target original constructor remainder");
                for (int i = 0; i < added.size(); i++) reverse.removeInstruction(insertion);
                reversedMethods.add(new ImmutableMethod(m.getDefiningClass(), m.getName(), m.getParameters(),
                    m.getReturnType(), m.getAccessFlags(), m.getAnnotations(), m.getHiddenApiRestrictions(), reverse));
            }
            reversedClasses.add(new ImmutableClassDef(c.getType(), c.getAccessFlags(), c.getSuperclass(),
                c.getInterfaces(), c.getSourceFile(), c.getAnnotations(), c.getFields(), reversedMethods));
        }
        String fullBefore = args[2] + ".full-before.dex", fullReversed = args[2] + ".full-reversed.dex";
        writePreserved(original, fullBefore, originalNames, false);
        writePreserved(new ImmutableDexFile(original.getOpcodes(), reversedClasses), fullReversed, originalNames, false);
        require(Arrays.equals(Files.readAllBytes(Path.of(fullBefore)), Files.readAllBytes(Path.of(fullReversed))),
                "constructor insertion does not reverse exactly to canonical original DEX");
        System.out.println("PATCHED constructor=1 original_classes=" + original.getClasses().size()
                + " unchanged_manager_methods=" + unchangedMethods + " helper_classes=" + helpers
                + " inserted_instructions=" + added.size() + " package_scope=Tips_only legacy_branch=verified canonical_reverse=exact");
    }
}
