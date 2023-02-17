/**
 * MIT License
 *
 * Copyright (c) 2020 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

package com.ifx.server.tss;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.util.encoders.Hex;
import tss.*;
import tss.tpm.*;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

public class Utils {

    // TCG EK template : https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
    private static final TPMT_PUBLIC EK_Template = new TPMT_PUBLIC(
            // TPMI_ALG_HASH    nameAlg
            TPM_ALG_ID.SHA256,
            // TPMA_OBJECT  objectAttributes
            new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.decrypt, TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent,
                    TPMA_OBJECT.adminWithPolicy, TPMA_OBJECT.sensitiveDataOrigin),
            // TPM2B_DIGEST authPolicy
            Helpers.fromHex("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa"),
            // TPMU_PUBLIC_PARMS    parameters
            new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB)
                    , new TPMS_NULL_ASYM_SCHEME(), 2048, 0),
            // TPMU_PUBLIC_ID       unique: 256 bytes long of zero
            new TPM2B_PUBLIC_KEY_RSA(new byte[256]));

    /**
     * Verify x509 certificate
     *
     * @param toVerify
     * @param signingCert
     * @return success or fail
     */
    public static boolean verifySignature(X509Certificate toVerify, X509Certificate signingCert) {
        if (!toVerify.getIssuerDN().equals(signingCert.getSubjectDN())) return false;
        try {
            toVerify.verify(signingCert.getPublicKey());
            return true;
        } catch (Exception e) {
            // CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
            return false;
        }
    }

    /**
     * Generate random
     *
     * @return
     */
    public static byte[] getRandom(int size) throws Exception {
        byte[] ba = Helpers.getRandom(size);
        return ba;
    }

    public static byte[] encryptAesCfb(byte[] key, byte[] data) throws Exception {
        return Crypto.cfbEncrypt(true, TPM_ALG_ID.AES, key, new byte[0], data);
    }

    public static byte[] decryptAesCfb(byte[] key, byte[] data) throws Exception {
        return Crypto.cfbEncrypt(false, TPM_ALG_ID.AES, key, new byte[0], data);
    }

    /**
     * Calculate TPM key's Name according to TPM standard
     * A key's Name is a digest of its public data
     *
     * @param pubKey
     * @return name
     */
    public static byte[] getKeyName(TPMT_PUBLIC pubKey) throws Exception {
        return pubKey.getName();
    }

    public static TPMT_PUBLIC rxConvoyPubKey(String pubKey) throws Exception {
        TPM2B_PUBLIC pub = TPM2B_PUBLIC.fromTpm(Hex.decode(pubKey));
        return pub.publicArea;
    }

    public static String encodeEkPubKey(RSAPublicKey key) throws Exception {
        BigInteger big = key.getModulus();
        byte[] pubKey = big.toByteArray();
        // Convert BigInteger to byte array may force an extra byte as a sign bit
        // , remove it...
        if ((pubKey.length % 8) != 0) {
            byte[] tmp = new byte[pubKey.length - 1];
            System.arraycopy(pubKey, 1, tmp, 0, pubKey.length - 1);
            pubKey = tmp;
        }
        TPMT_PUBLIC ekPub = EK_Template;
        ((TPM2B_PUBLIC_KEY_RSA)ekPub.unique).buffer = pubKey;
        TPM2B_PUBLIC pub = new TPM2B_PUBLIC(ekPub);
        return Hex.toHexString(pub.toTpm());
    }

    public static String getPubKey(RSAPublicKey key) throws Exception {
        BigInteger big = key.getModulus();
        byte[] pubKey = big.toByteArray();
        // Convert BigInteger to byte array may force an extra byte as a sign bit
        // , remove it...
        if ((pubKey.length % 8) != 0) {
            byte[] tmp = new byte[pubKey.length - 1];
            System.arraycopy(pubKey, 1, tmp, 0, pubKey.length - 1);
            pubKey = tmp;
        }
        return Hex.toHexString(pubKey);
    }

    public static String object2Json(Object obj) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(obj);
    }

    public static <T> T json2Object(String json, Class<T> type) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(json, type);
    }

    public static BigInteger toBigInteger(byte[] ba) throws Exception {
        byte[] unsignedBa = new byte[ba.length + 1];
        System.arraycopy(ba, 0, unsignedBa, 1, ba.length);
        return new BigInteger(unsignedBa);
    }

    ///////////////////////////////////////////////////
    /* private */
    ///////////////////////////////////////////////////

    /**
     * Convert hex string to byte array
     * "000102" -> {0x00, 0x01, 0x02}
     * @param s hex string
     * @return byte array
     */
    static byte[] hexStringToByteArray(String s) throws Exception {
        return Hex.decode(s);
    }

    /**
     * Convert byte array to hex string
     * {0x00, 0x01, 0x02} -> "000102"
     * @param ba byte array
     * @return hex string
     */
    static String byteArrayToHexString(byte[] ba) throws Exception {
        return Hex.toHexString(ba);
    }

}
