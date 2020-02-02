/*
 * Copyright (C) by MinterTeam. 2018
 * @link <a href="https://github.com/MinterTeam">Org Github</a>
 * @link <a href="https://github.com/edwardstock">Maintainer Github</a>
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.edwardstock.secp256k1;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * This class holds native methods to handle ECDSA verification.
 */
public final class NativeSecp256k1 {
    public final static String SONAME = "secp256k1_jni";
    public final static String[] LIB_FILES = new String[]{"libsecp256k1_jni.so"};

    private static final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();
    private static final Lock r = rwl.readLock();
    private static final Lock w = rwl.writeLock();
    private static ThreadLocal<ByteBuffer> nativeECDSABuffer = new ThreadLocal<>();

    private static NativeSecp256k1 INSTANCE;
    private static Throwable sError = null;
    private static boolean sEnabled = true; //true if the library is loaded

    private NativeSecp256k1() {
    }

    public static void init() {
        if (INSTANCE == null) {
            try {
                System.loadLibrary(SONAME);
            } catch (UnsatisfiedLinkError e) {
                System.err.println(String.format("Unable to load %s in %s: %s", SONAME, System.getProperty("java.library.path"), e.getMessage()));
                sError = e;
                setEnabled(false);
            }

            INSTANCE = new NativeSecp256k1();
        }
    }

    public static Throwable getError() {
        return sError;
    }

    public static boolean isEnabled() {
        return sEnabled;
    }

    /**
     * Use this carefully, only if you have loaded native libs by yourself
     * @param enabled
     */
    public static void setEnabled(boolean enabled) {
        sEnabled = enabled;
    }

    public static long contextCreate() {
        if (!isEnabled()) {
            return 0;//nullptr
        }

        return secp256k1_init_context();
    }

    /**
     * Verifies the given secp256k1 signature in native code.
     * Calling when sEnabled == false is undefined (probably library not loaded)
     * @param data The data which was signed, must be exactly 32 bytes
     * @param signature The signature
     * @param pub The public key which did the signing
     */
    public static boolean verify(long ctx, byte[] data, byte[] signature, byte[] pub) throws NativeSecp256k1Util.AssertFailException {
        NativeSecp256k1Util.checkArgument(data.length == 32 && signature.length <= 520 && pub.length <= 520);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < 520) {
            byteBuff = ByteBuffer.allocateDirect(520);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(data);
        byteBuff.put(signature);
        byteBuff.put(pub);

        r.lock();
        try {
            return secp256k1_ecdsa_verify(byteBuff, ctx, signature.length, pub.length) == 1;
        } finally {
            r.unlock();
        }
    }

    /**
     * libsecp256k1 Create an ECDSA signature.
     * @param ctx pointer context
     * @param data Message hash, 32 bytes byte array of signature
     * @param secret Secret key, 32 bytes
     *         <p>
     *         Return values
     */
    public static byte[] sign(long ctx, byte[] data, byte[] secret) throws NativeSecp256k1Util.AssertFailException {
        NativeSecp256k1Util.checkArgument(data.length == 32 && secret.length <= 32);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < 32 + 32) {
            byteBuff = ByteBuffer.allocateDirect(32 + 32);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(data);
        byteBuff.put(secret);

        byte[][] retByteArray;

        r.lock();
        try {
            retByteArray = secp256k1_ecdsa_sign(byteBuff, ctx);
        } finally {
            r.unlock();
        }

        byte[] sigArr = retByteArray[0];
        int sigLen = new BigInteger(new byte[]{retByteArray[1][0]}).intValue();
        int retVal = new BigInteger(new byte[]{retByteArray[1][1]}).intValue();

        NativeSecp256k1Util.assertEquals(sigArr.length, sigLen, "Got bad signature length.");

        return retVal == 0 ? new byte[0] : sigArr;
    }

    /**
     * libsecp256k1 Create an ECDSA recoverable signature.
     * @param data Message hash, 32 bytes
     * @param secret Secret key, 64 bytes
     *         <p>
     *         Return values
     * @return Split byte array signature
     */
    public static RecoverableSignature signRecoverableSerialized(long ctx, byte[] data, byte[] secret) {
        NativeSecp256k1Util.checkArgument(data.length == 32 && secret.length == 32);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < 32 + 32) {
            byteBuff = ByteBuffer.allocateDirect(32 + 32);
            byteBuff.order(ByteOrder.LITTLE_ENDIAN);
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(data);
        byteBuff.put(secret);

        byte[][] retByteArray;

        r.lock();
        try {
            retByteArray = secp256k1_ecdsa_sign_recoverable_serialized(byteBuff, ctx);
        } finally {
            r.unlock();
        }

        if(retByteArray == null) {
            return null;
        }

        if (retByteArray.length != 3) {
            return null;
        }

        return new RecoverableSignature(retByteArray[0], retByteArray[1], retByteArray[2]);
    }

    /**
     * libsecp256k1 Seckey Verify - returns 1 if valid, 0 if invalid
     * @param secretKey ECDSA Secret key, 32 bytes
     */
    public static boolean secKeyVerify(long ctx, byte[] secretKey) {
        NativeSecp256k1Util.checkArgument(secretKey.length == 32, "Secret length must be 32 bytes");

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < secretKey.length) {
            byteBuff = ByteBuffer.allocateDirect(secretKey.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(secretKey);

        r.lock();
        try {
            return secp256k1_ec_seckey_verify(byteBuff, ctx) == 1;
        } finally {
            r.unlock();
        }
    }

    /**
     * libsecp256k1 Compute Pubkey - computes public key from secret key
     * @param seckey ECDSA Secret key, 32 bytes
     *         <p>
     *         Return values
     * @param compressed Compressed or not public key
     * @return ECDSA Public key, 33 or 65 bytes
     */
    //TODO add a 'compressed' arg
    public static byte[] computePubkey(long ctx, byte[] seckey, boolean compressed) {
        NativeSecp256k1Util.checkArgument(seckey.length == 32);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < seckey.length) {
            byteBuff = ByteBuffer.allocateDirect(seckey.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(seckey);

        byte[][] retByteArray;

        r.lock();
        try {
            retByteArray = secp256k1_ec_pubkey_create(byteBuff, ctx, compressed);
        } finally {
            r.unlock();
        }

        byte[] pubArr = retByteArray[0];
        int pubLen = new BigInteger(new byte[]{retByteArray[1][0]}).intValue();
        int retVal = new BigInteger(new byte[]{retByteArray[1][1]}).intValue();

        NativeSecp256k1Util.assertEquals(pubArr.length, pubLen, "Got bad pubkey length.");

        return retVal == 0 ? new byte[0] : pubArr;
    }

    /**
     * libsecp256k1 Cleanup - This destroys the secp256k1 context object
     * This should be called at the end of the program for proper contextCleanup of the context.
     */
    public static synchronized void contextCleanup(long ctx) {
        w.lock();
        try {
            secp256k1_destroy_context(ctx);
        } finally {
            w.unlock();
        }
    }

    public static long cloneContext(long ctx) {
        r.lock();
        try {
            return secp256k1_ctx_clone(ctx);
        } finally {
            r.unlock();
        }
    }

    /**
     * libsecp256k1 PrivKey Tweak-Mul - Tweak privkey by multiplying to it
     * @param privkey 32-byte seckey
     * @param tweak some bytes to tweak with
     */
    public static byte[] privKeyTweakMul(long ctx, byte[] privkey, byte[] tweak) throws NativeSecp256k1Util.AssertFailException {
        NativeSecp256k1Util.checkArgument(privkey.length == 32);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < privkey.length + tweak.length) {
            byteBuff = ByteBuffer.allocateDirect(privkey.length + tweak.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(privkey);
        byteBuff.put(tweak);

        byte[][] retByteArray;
        r.lock();
        try {
            retByteArray = secp256k1_privkey_tweak_mul(byteBuff, ctx);
        } finally {
            r.unlock();
        }

        byte[] privArr = retByteArray[0];

        int privLen = (byte) new BigInteger(new byte[]{retByteArray[1][0]}).intValue() & 0xFF;
        int retVal = new BigInteger(new byte[]{retByteArray[1][1]}).intValue();

        NativeSecp256k1Util.assertEquals(privArr.length, privLen, "Got bad pubkey length.");

        NativeSecp256k1Util.assertEquals(retVal, 1, "Failed return value check.");

        return privArr;
    }

    /**
     * libsecp256k1 PrivKey Tweak-Add - Tweak privkey by adding to it
     * @param privkey 32-byte seckey
     * @param tweak some bytes to tweak with
     */
    public static byte[] privKeyTweakAdd(long ctx, byte[] privkey, byte[] tweak) throws NativeSecp256k1Util.AssertFailException {
        NativeSecp256k1Util.checkArgument(privkey.length == 32);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < privkey.length + tweak.length) {
            byteBuff = ByteBuffer.allocateDirect(privkey.length + tweak.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(privkey);
        byteBuff.put(tweak);

        byte[][] retByteArray;
        r.lock();
        try {
            retByteArray = secp256k1_privkey_tweak_add(byteBuff, ctx);
        } finally {
            r.unlock();
        }

        byte[] privArr = retByteArray[0];

        int privLen = (byte) new BigInteger(new byte[]{retByteArray[1][0]}).intValue() & 0xFF;
        int retVal = new BigInteger(new byte[]{retByteArray[1][1]}).intValue();

        NativeSecp256k1Util.assertEquals(privArr.length, privLen, "Got bad pubkey length.");

        NativeSecp256k1Util.assertEquals(retVal, 1, "Failed return value check.");

        return privArr;
    }

    /**
     * libsecp256k1 PubKey Tweak-Add - Tweak pubkey by adding to it
     * @param tweak some bytes to tweak with
     * @param pubkey 32-byte seckey
     */
    public static byte[] pubKeyTweakAdd(long ctx, byte[] pubkey, byte[] tweak) throws NativeSecp256k1Util.AssertFailException {
        NativeSecp256k1Util.checkArgument(pubkey.length == 33 || pubkey.length == 65);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < pubkey.length + tweak.length) {
            byteBuff = ByteBuffer.allocateDirect(pubkey.length + tweak.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(pubkey);
        byteBuff.put(tweak);

        byte[][] retByteArray;
        r.lock();
        try {
            retByteArray = secp256k1_pubkey_tweak_add(byteBuff, ctx, pubkey.length);
        } finally {
            r.unlock();
        }

        byte[] pubArr = retByteArray[0];

        int pubLen = (byte) new BigInteger(new byte[]{retByteArray[1][0]}).intValue() & 0xFF;
        int retVal = new BigInteger(new byte[]{retByteArray[1][1]}).intValue();

        NativeSecp256k1Util.assertEquals(pubArr.length, pubLen, "Got bad pubkey length.");

        NativeSecp256k1Util.assertEquals(retVal, 1, "Failed return value check.");

        return pubArr;
    }

    /**
     * libsecp256k1 PubKey Tweak-Mul - Tweak pubkey by multiplying to it
     * @param tweak some bytes to tweak with
     * @param pubkey 32-byte seckey
     */
    public static byte[] pubKeyTweakMul(long ctx, byte[] pubkey, byte[] tweak) throws NativeSecp256k1Util.AssertFailException {
        NativeSecp256k1Util.checkArgument(pubkey.length == 33 || pubkey.length == 65);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < pubkey.length + tweak.length) {
            byteBuff = ByteBuffer.allocateDirect(pubkey.length + tweak.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(pubkey);
        byteBuff.put(tweak);

        byte[][] retByteArray;
        r.lock();
        try {
            retByteArray = secp256k1_pubkey_tweak_mul(byteBuff, ctx, pubkey.length);
        } finally {
            r.unlock();
        }

        byte[] pubArr = retByteArray[0];

        int pubLen = (byte) new BigInteger(new byte[]{retByteArray[1][0]}).intValue() & 0xFF;
        int retVal = new BigInteger(new byte[]{retByteArray[1][1]}).intValue();

        NativeSecp256k1Util.assertEquals(pubArr.length, pubLen, "Got bad pubkey length.");

        NativeSecp256k1Util.assertEquals(retVal, 1, "Failed return value check.");

        return pubArr;
    }

    /**
     * libsecp256k1 create ECDH secret - constant time ECDH calculation
     * @param seckey byte array of secret key used in exponentiaion
     * @param pubkey byte array of public key used in exponentiaion
     */
    public static byte[] createECDHSecret(long ctx, byte[] seckey, byte[] pubkey) throws NativeSecp256k1Util.AssertFailException {
        NativeSecp256k1Util.checkArgument(seckey.length <= 32 && pubkey.length <= 65);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < 32 + pubkey.length) {
            byteBuff = ByteBuffer.allocateDirect(32 + pubkey.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(seckey);
        byteBuff.put(pubkey);

        byte[][] retByteArray;
        r.lock();
        try {
            retByteArray = secp256k1_ecdh(byteBuff, ctx, pubkey.length);
        } finally {
            r.unlock();
        }

        byte[] resArr = retByteArray[0];
        int retVal = new BigInteger(new byte[]{retByteArray[1][0]}).intValue();

        NativeSecp256k1Util.assertEquals(resArr.length, 32, "Got bad result length.");
        NativeSecp256k1Util.assertEquals(retVal, 1, "Failed return value check.");

        return resArr;
    }

    /**
     * libsecp256k1 randomize - updates the context randomization
     * @param seed 32-byte random seed
     */
    public static synchronized boolean randomize(long ctx, byte[] seed) throws NativeSecp256k1Util.AssertFailException {
        NativeSecp256k1Util.checkArgument(seed.length == 32 || seed == null);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < seed.length) {
            byteBuff = ByteBuffer.allocateDirect(seed.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(seed);

        w.lock();
        try {
            return secp256k1_context_randomize(byteBuff, ctx) == 1;
        } finally {
            w.unlock();
        }
    }

    static native void secp256k1_destroy_context(long context);

    private static native long secp256k1_ctx_clone(long context);

    private static native int secp256k1_context_randomize(ByteBuffer byteBuff, long context);

    private static native byte[][] secp256k1_privkey_tweak_add(ByteBuffer byteBuff, long context);

    private static native byte[][] secp256k1_privkey_tweak_mul(ByteBuffer byteBuff, long context);

    private static native byte[][] secp256k1_pubkey_tweak_add(ByteBuffer byteBuff, long context, int pubLen);

    private static native byte[][] secp256k1_pubkey_tweak_mul(ByteBuffer byteBuff, long context, int pubLen);

    private static native int secp256k1_ecdsa_verify(ByteBuffer byteBuff, long context, int sigLen, int pubLen);

    private static native byte[][] secp256k1_ecdsa_sign(ByteBuffer byteBuff, long context);

    private static native byte[][] secp256k1_ecdsa_sign_recoverable_serialized(ByteBuffer byteBuff, long context);

    private static native int secp256k1_ec_seckey_verify(ByteBuffer byteBuff, long context);

    private static native byte[][] secp256k1_ec_pubkey_create(ByteBuffer byteBuff, long context, boolean compressed);

    private static native byte[][] secp256k1_ec_pubkey_parse(ByteBuffer byteBuff, long context, int inputLen);

    private static native byte[][] secp256k1_ecdh(ByteBuffer byteBuff, long context, int inputLen);

    private static native long secp256k1_init_context();

    public static final class RecoverableSignature {
        public byte[] r;
        public byte[] s;
        public byte[] v;

        RecoverableSignature(byte[] ir, byte[] is, byte[] iv) {
            r = ir;
            s = is;
            v = iv;
        }

        public byte[] toSign() {
            int n = 0;
            byte[] out = new byte[65];
            for (int i = 0; i < r.length; n++, i++) {
                out[n] = r[i];
            }
            for (int i = 0; i < s.length; n++, i++) {
                out[n] = s[i];
            }
            for (int i = 0; i < v.length; n++, i++) {
                out[n] = v[i];
            }

            return out;
        }
    }

}
