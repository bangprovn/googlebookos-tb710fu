// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

/** Fresh app-owned key only. The external owner controller handles normal SystemUI unlock. */
public final class AuthKeyProbe {
    private static void require(boolean value) {if(!value)throw new IllegalStateException("auth-key assertion failed");}
    private static boolean authFailure(GeneralSecurityException failure) {
        Throwable cause=failure;
        for(int depth=0;cause!=null && depth<4;depth++,cause=cause.getCause())
            if(cause instanceof UserNotAuthenticatedException)return true;
        return false;
    }
    private static boolean authenticationRefused(PrivateKey key) throws GeneralSecurityException {
        try {
            Signature signer=Signature.getInstance("SHA256withECDSA");
            signer.initSign(key);signer.update(new byte[]{1,2,3});signer.sign();return false;
        } catch(GeneralSecurityException failure) {
            if(authFailure(failure))return true;
            throw failure;
        }
    }
    private static void stage(Context context,String runId,String phase) throws Exception {
        File temp=new File(context.getFilesDir(),"auth-stage-"+runId+".tmp");
        JSONObject value=new JSONObject().put("run_id",runId).put("phase",phase).put("credential_received_by_app",false);
        try(FileOutputStream out=new FileOutputStream(temp)) {out.write(value.toString().getBytes(StandardCharsets.UTF_8));out.getFD().sync();}
        require(temp.renameTo(new File(context.getFilesDir(),"auth-stage-"+runId+".json")));
    }
    public static JSONObject run(Context context,String runId) throws Exception {
        require(runId.matches("[a-f0-9]{32}"));
        JSONObject row=new JSONObject().put("state","unknown").put("phase","preflight")
            .put("scope","Fresh ordinary-app five-second device-credential P-256 signing gate; not key attestation or StrongBox qualification")
            .put("credential_received_by_app",false).put("private_material_exported",false).put("attestation_verified",false);
        KeyStore store=null;boolean reserved=false;byte[] message=new byte[32],signed=null;
        String alias="gb-auth-probe-"+runId;
        try {
            KeyguardManager keyguard=(KeyguardManager)context.getSystemService(Context.KEYGUARD_SERVICE);
            require(keyguard!=null && keyguard.isDeviceSecure() && !keyguard.isDeviceLocked());
            store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
            require(!store.containsAlias(alias));reserved=true;
            KeyPairGenerator generator=KeyPairGenerator.getInstance("EC","AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_SIGN|KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(5,KeyProperties.AUTH_DEVICE_CREDENTIAL).build());
            KeyPair pair=generator.generateKeyPair();require(pair.getPrivate().getEncoded()==null);
            KeyInfo info=(KeyInfo)KeyFactory.getInstance("EC","AndroidKeyStore").getKeySpec(pair.getPrivate(),KeyInfo.class);
            row.put("user_authentication_required",info.isUserAuthenticationRequired())
                .put("authentication_validity_seconds",info.getUserAuthenticationValidityDurationSeconds())
                .put("authentication_type",info.getUserAuthenticationType())
                .put("reported_security_level",info.getSecurityLevel())
                .put("reported_hardware_auth_enforced",info.isUserAuthenticationRequirementEnforcedBySecureHardware());
            require(info.isUserAuthenticationRequired() && info.getUserAuthenticationValidityDurationSeconds()==5
                && info.getUserAuthenticationType()==KeyProperties.AUTH_DEVICE_CREDENTIAL);
            Thread.sleep(6000); // Expire any credential token predating key creation.
            boolean before=authenticationRefused(pair.getPrivate());row.put("before_authentication_rejected",before);require(before);
            stage(context,runId,"waiting_for_normal_unlock");row.put("phase","waiting_for_normal_unlock");
            long deadline=SystemClock.elapsedRealtime()+20000;
            while(!keyguard.isDeviceLocked() && SystemClock.elapsedRealtime()<deadline)Thread.sleep(50);
            require(keyguard.isDeviceLocked());row.put("normal_lock_observed",true);stage(context,runId,"normal_lock_observed");
            deadline=SystemClock.elapsedRealtime()+50000;
            while(keyguard.isDeviceLocked() && SystemClock.elapsedRealtime()<deadline)Thread.sleep(50);
            require(!keyguard.isDeviceLocked());row.put("normal_unlock_observed",true);
            row.put("phase","sign_after_unlock");
            new SecureRandom().nextBytes(message);
            Signature signer=Signature.getInstance("SHA256withECDSA");
            // Keyguard dismissal can precede delivery of the authentication token.
            // Retry only the app-owned crypto operation, never the credential input.
            long unlockedAt=SystemClock.elapsedRealtime();int attempts=0;
            while(true) {
                attempts++;
                try {signer.initSign(pair.getPrivate());signer.update(message);signed=signer.sign();break;}
                catch(GeneralSecurityException failure) {
                    long wait=SystemClock.elapsedRealtime()-unlockedAt;
                    row.put("post_unlock_auth_wait_ms",wait).put("post_unlock_sign_attempts",attempts);
                    if(!authFailure(failure) || wait>=2000 || attempts>=41)throw failure;
                    Thread.sleep(50);
                }
            }
            row.put("post_unlock_auth_wait_ms",SystemClock.elapsedRealtime()-unlockedAt).put("post_unlock_sign_attempts",attempts);
            signer.initVerify(pair.getPublic());signer.update(message);boolean verified=signer.verify(signed);require(verified);
            message[0]^=1;signer.initVerify(pair.getPublic());signer.update(message);boolean tamper=!signer.verify(signed);require(tamper);
            row.put("signature_after_unlock_verified",verified).put("changed_message_rejected",tamper);
            stage(context,runId,"waiting_for_expiry");Thread.sleep(6500);
            boolean expired=authenticationRefused(pair.getPrivate());row.put("after_expiry_rejected",expired);require(expired);
            row.put("phase","authentication_gate_observed");
            if((info.getSecurityLevel()==KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                || info.getSecurityLevel()==KeyProperties.SECURITY_LEVEL_STRONGBOX)
                && info.isUserAuthenticationRequirementEnforcedBySecureHardware())row.put("state","compatible");
        } catch(Throwable failure) {row.put("state","unknown").put("error_class",failure.getClass().getName());}
        finally {
            Arrays.fill(message,(byte)0);if(signed!=null)Arrays.fill(signed,(byte)0);
            if(reserved && store!=null) {
                try {store.deleteEntry(alias);boolean removed=!store.containsAlias(alias);row.put("owned_keys_removed",removed);if(!removed)row.put("state","unknown");}
                catch(Throwable failure) {row.put("owned_keys_removed",false).put("cleanup_error_class",failure.getClass().getName()).put("state","unknown");}
            }
        }
        return new JSONObject().put("status","observed").put("results",new JSONArray().put(row));
    }
}
