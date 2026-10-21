// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.functional;

import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.os.Process;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

/** Owned shell-UID probe. Never exports key material, certificates or user data. */
public final class AndroidFunctionalProbe {
    private static void require(boolean ok) {
        if (!ok) throw new IllegalStateException("functional assertion failed");
    }
    private static int shader(int type, String source) {
        int shader = GLES20.glCreateShader(type);
        GLES20.glShaderSource(shader, source);
        GLES20.glCompileShader(shader);
        int[] status = new int[1];
        GLES20.glGetShaderiv(shader, GLES20.GL_COMPILE_STATUS, status, 0);
        if (status[0] != GLES20.GL_TRUE) {
            GLES20.glDeleteShader(shader);
            throw new IllegalStateException("shader compilation failed");
        }
        return shader;
    }
    private static JSONObject graphics() throws Exception {
        EGLDisplay display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
        EGLSurface surface = EGL14.EGL_NO_SURFACE;
        EGLContext context = EGL14.EGL_NO_CONTEXT;
        int vertex = 0, fragment = 0, program = 0;
        try {
            int[] version = new int[2];
            require(display != EGL14.EGL_NO_DISPLAY && EGL14.eglInitialize(display, version, 0, version, 1));
            EGLConfig[] configs = new EGLConfig[1];
            int[] count = new int[1];
            require(EGL14.eglChooseConfig(display, new int[] {
                EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                EGL14.EGL_RED_SIZE, 8, EGL14.EGL_GREEN_SIZE, 8,
                EGL14.EGL_BLUE_SIZE, 8, EGL14.EGL_ALPHA_SIZE, 8, EGL14.EGL_NONE
            }, 0, configs, 0, 1, count, 0) && count[0] == 1);
            context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT,
                new int[] {EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE}, 0);
            surface = EGL14.eglCreatePbufferSurface(display, configs[0],
                new int[] {EGL14.EGL_WIDTH, 16, EGL14.EGL_HEIGHT, 16, EGL14.EGL_NONE}, 0);
            require(context != EGL14.EGL_NO_CONTEXT && surface != EGL14.EGL_NO_SURFACE);
            require(EGL14.eglMakeCurrent(display, surface, surface, context));
            vertex = shader(GLES20.GL_VERTEX_SHADER,
                "attribute vec2 p; void main(){gl_Position=vec4(p,0.0,1.0);}");
            fragment = shader(GLES20.GL_FRAGMENT_SHADER,
                "precision mediump float; uniform vec4 c; void main(){gl_FragColor=c;}");
            program = GLES20.glCreateProgram();
            GLES20.glAttachShader(program, vertex);
            GLES20.glAttachShader(program, fragment);
            GLES20.glBindAttribLocation(program, 0, "p");
            GLES20.glLinkProgram(program);
            int[] linked = new int[1];
            GLES20.glGetProgramiv(program, GLES20.GL_LINK_STATUS, linked, 0);
            require(linked[0] == GLES20.GL_TRUE);
            GLES20.glUseProgram(program);
            FloatBuffer vertices = ByteBuffer.allocateDirect(24).order(ByteOrder.nativeOrder()).asFloatBuffer();
            vertices.put(new float[] {-1,-1,3,-1,-1,3}).position(0);
            GLES20.glVertexAttribPointer(0, 2, GLES20.GL_FLOAT, false, 0, vertices);
            GLES20.glEnableVertexAttribArray(0);
            GLES20.glViewport(0, 0, 16, 16);
            GLES20.glDisable(GLES20.GL_DITHER);
            int colorLocation = GLES20.glGetUniformLocation(program, "c");
            require(colorLocation >= 0);
            ByteBuffer pixels = ByteBuffer.allocateDirect(16 * 16 * 4);
            int[][] colors = {{255,0,0,255},{0,255,0,255},{0,0,255,255},{64,128,192,255}};
            int maxError = 0;
            for (int frame = 0; frame < 16; frame++) {
                int[] color = colors[frame % colors.length];
                GLES20.glUniform4f(colorLocation, color[0]/255f, color[1]/255f, color[2]/255f, 1f);
                GLES20.glDrawArrays(GLES20.GL_TRIANGLES, 0, 3);
                GLES20.glReadPixels(0, 0, 16, 16, GLES20.GL_RGBA, GLES20.GL_UNSIGNED_BYTE, pixels);
                require(GLES20.glGetError() == GLES20.GL_NO_ERROR);
                for (int i = 0; i < 16*16*4; i++) {
                    int error = Math.abs((pixels.get(i) & 255) - color[i % 4]);
                    maxError = Math.max(error, maxError);
                    require(error <= 3);
                }
            }
            JSONObject result = new JSONObject();
            result.put("state", "compatible");
            result.put("scope", "Android EGL pbuffer GLES2 shader draw and RGBA readback only");
            result.put("frames_verified", 16).put("pixels_per_frame", 256).put("max_channel_error", maxError);
            result.put("renderer", GLES20.glGetString(GLES20.GL_RENDERER));
            result.put("vendor", GLES20.glGetString(GLES20.GL_VENDOR));
            result.put("gl_version", GLES20.glGetString(GLES20.GL_VERSION));
            result.put("physical_panel_or_guest_gpu_verified", false);
            return result;
        } finally {
            if (program != 0) GLES20.glDeleteProgram(program);
            if (fragment != 0) GLES20.glDeleteShader(fragment);
            if (vertex != 0) GLES20.glDeleteShader(vertex);
            EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
            if (surface != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(display, surface);
            if (context != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(display, context);
            if (display != EGL14.EGL_NO_DISPLAY) EGL14.eglTerminate(display);
            EGL14.eglReleaseThread();
        }
    }
    private static String alias(String runId, String kind) {
        return "gb-functional-v1-" + runId + "-" + kind;
    }
    private static boolean initializeKeyStoreProvider() throws Exception {
        // app_process has no Application.bindApplication() startup. Install the
        // platform JCA provider in this process only, as normal app startup does.
        boolean installed = Security.getProvider("AndroidKeyStore") == null;
        if (installed) {
            Class.forName("android.security.keystore2.AndroidKeyStoreProvider")
                .getMethod("install").invoke(null);
        }
        require(Security.getProvider("AndroidKeyStore") != null);
        return installed;
    }
    private static void cleanup(String runId) throws Exception {
        initializeKeyStoreProvider();
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        for (String kind : new String[] {"aes", "ec"}) {
            String name = alias(runId, kind);
            store.deleteEntry(name);
            require(!store.containsAlias(name));
        }
    }
    private static JSONObject keystore(String runId) throws Exception {
        boolean providerInstalled = initializeKeyStoreProvider();
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        String aesAlias = alias(runId, "aes"), ecAlias = alias(runId, "ec");
        require(!store.containsAlias(aesAlias) && !store.containsAlias(ecAlias));
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(aesAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build());
            SecretKey key = generator.generateKey();
            require(key.getEncoded() == null);
            KeyInfo aesInfo = (KeyInfo)SecretKeyFactory.getInstance("AES", "AndroidKeyStore")
                .getKeySpec(key, KeyInfo.class);
            byte[] message = new byte[32];
            new SecureRandom().nextBytes(message);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(message);
            byte[] iv = cipher.getIV();
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            require(Arrays.equals(message, cipher.doFinal(encrypted)));
            encrypted[encrypted.length - 1] ^= 1;
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            boolean tamperRejected = false;
            try { cipher.doFinal(encrypted); } catch (AEADBadTagException expected) { tamperRejected = true; }
            require(tamperRejected);
            KeyPairGenerator pairs = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            pairs.initialize(new KeyGenParameterSpec.Builder(ecAlias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256).build());
            KeyPair pair = pairs.generateKeyPair();
            require(pair.getPrivate().getEncoded() == null);
            KeyInfo ecInfo = KeyFactory.getInstance("EC", "AndroidKeyStore")
                .getKeySpec(pair.getPrivate(), KeyInfo.class);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(pair.getPrivate()); signature.update(message);
            byte[] signed = signature.sign();
            signature.initVerify(pair.getPublic()); signature.update(message);
            require(signature.verify(signed));
            message[0] ^= 1;
            signature.initVerify(pair.getPublic()); signature.update(message);
            require(!signature.verify(signed));
            JSONObject result = new JSONObject();
            result.put("state", "compatible").put("scope", "Fresh unauthed shell-UID keys only");
            result.put("aes256_gcm_roundtrip", true).put("gcm_tamper_rejected", true);
            result.put("p256_signature_verified", true).put("changed_message_rejected", true);
            result.put("aes_reported_security_level", aesInfo.getSecurityLevel());
            result.put("ec_reported_security_level", ecInfo.getSecurityLevel());
            result.put("private_material_exported", false).put("attestation_verified", false);
            result.put("owner_auth_bound_keys_verified", false);
            result.put("provider_initialized_in_probe_process", providerInstalled);
            return result;
        } finally {
            // Exact aliases in this invocation's fresh namespace only.
            store.deleteEntry(aesAlias); store.deleteEntry(ecAlias);
            require(!store.containsAlias(aesAlias) && !store.containsAlias(ecAlias));
        }
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 2 && Process.myUid() == 2000);
        require(args[1].matches("[a-f0-9]{32}"));
        if (args[0].equals("cleanup")) {
            cleanup(args[1]);
            System.out.println("GB_ANDROID_FUNCTIONAL_CLEANUP:" + args[1]);
            return;
        }
        require(args[0].equals("run"));
        JSONObject report = new JSONObject();
        report.put("schema_version", 1).put("probe", "owned_android_functional_v1").put("uid", 2000);
        try { report.put("graphics", graphics()); }
        catch (Throwable error) { report.put("graphics", new JSONObject().put("state", "unknown")
            .put("error_class", error.getClass().getName())); }
        try { report.put("keystore", keystore(args[1]).put("owned_keys_removed", true)); }
        catch (Throwable error) { report.put("keystore", new JSONObject().put("state", "unknown")
            .put("error_class", error.getClass().getName())); }
        report.put("full_port_verified", false).put("user_content_collected", false);
        System.out.println("GB_ANDROID_FUNCTIONAL:" + report.toString());
    }
}
