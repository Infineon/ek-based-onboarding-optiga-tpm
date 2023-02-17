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

import org.bouncycastle.util.encoders.Hex;
import tss.Crypto;
import tss.TpmException;
import tss.Tss;
import tss.tpm.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class DuplicateRSA extends Duplicate {

    private byte[] data;
    private TPMU_SIGNATURE signature;
    private static final TPMT_SYM_DEF_OBJECT NullSymDef = new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL,  0, TPM_ALG_ID.NULL);
    private static final TPMT_PUBLIC template = new TPMT_PUBLIC(
            // TPMI_ALG_HASH nameAlg
            TPM_ALG_ID.SHA256,
            // TPMA_OBJECT  objectAttributes
            new TPMA_OBJECT(TPMA_OBJECT.sign, TPMA_OBJECT.sensitiveDataOrigin, TPMA_OBJECT.userWithAuth),
            // TPM2B_DIGEST authPolicy
            new byte[0],
            // TPMU_PUBLIC_PARMS    parameters
            new TPMS_RSA_PARMS(NullSymDef, new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256), 2048, 65537),
            // TPMU_PUBLIC_ID       unique
            new TPM2B_PUBLIC_KEY_RSA());

    public DuplicateRSA() throws Exception {
        super();
    }

    public void genKey() throws Exception {
        //key = Tss.createKey(template); //workaround to not use default crypto provider
        key = createKey(template);
    }

    public void rxConvoySignature(String data, String signature) throws Exception {
        this.data = Hex.decode(data);
        TPMU_SIGNATURE sig = TPMS_SIGNATURE_RSASSA.fromTpm(Hex.decode(signature));
        this.signature = sig;
    }

    public boolean verify() throws Exception {
        return key.PublicPart.validateSignature(data, signature);
    }

    public void duplicate(TPMT_PUBLIC parentPub) throws Exception {
        byte[] swKeyAuthValue = new byte[] {0};
        TPMT_SENSITIVE sens = new TPMT_SENSITIVE(swKeyAuthValue, new byte[0], new TPM2B_PRIVATE_KEY_RSA(key.PrivatePart));
        duplicate = createDuplicationBlob(parentPub, key.PublicPart, sens,
                new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES,  128, TPM_ALG_ID.CFB));
        // dupBlob.EncryptionKey == dupBlob.InnerWrapperKey // A key use to encrypt duplicate object as first layer encryption
        // dupBlob.EncryptedSeed; // A seed encrypted by parent key (srk); seed to derive a key for second layer encryption of duplicate object
        // dupBlob.DuplicateObject; // Encrypted key object to migrate
    }

    ///////////////////////////////////////////
    /* Private */
    ///////////////////////////////////////////

    /**
     * Clone of Microsoft Tss.createKey()
     *
     * @param pub
     * @return
     */
    static Tss.Key createKey(TPMT_PUBLIC pub)
    {
        Tss.Key tssKey = new Tss.Key();

        if(pub.GetUnionSelector_parameters()== TPM_ALG_ID.RSA.toInt())
        {

            TPMS_RSA_PARMS parms = (TPMS_RSA_PARMS) pub.parameters;
            int keySize = parms.keyBits;
            int exponent = parms.exponent;
            Crypto.RsaKeyPair newKey = createRsaKey(keySize, exponent);

            byte[] pubKey = bigIntToTpmInt(newKey.PublicKey, keySize);

            tssKey.PublicPart = new TPMT_PUBLIC(pub.nameAlg, pub.objectAttributes, pub.authPolicy, pub.parameters,
                    new TPM2B_PUBLIC_KEY_RSA(pubKey));
            tssKey.PrivatePart = bigIntToTpmInt(newKey.PrivateKey, keySize/2);
        }
        else
            throw new TpmException("Unsupported alg");
        return tssKey;
    }

    /**
     * Clone of Microsoft tss.Crypto.bigIntToTpmInt()
     *
     * @param x
     * @param keySize
     * @return
     */
    static byte[] bigIntToTpmInt(BigInteger x, int keySize)
    {
        int numBytes = keySize/8;
        byte[] key = x.toByteArray();
        byte[] ret = new byte[numBytes];

        // offset may be positive (the BigInt has a leading zero sign-byte) or negative (the BigInt does not use all the bytes)
        int offset = key.length - numBytes;
        // todo remove - sanity check
        if((offset>5) || (offset< -5))throw new RuntimeException("help");

        for(int j=0;j<numBytes;j++)
        {
            if(j+offset<0)continue;
            ret[j] = key[j+offset];
        }
        return ret;
    }

    /**
     * Clone of Microsoft tss.Crypto.createRsaKey() with following modification
     *
     * Key created by default crypto provider "SunRsaSign" has low RSA key quality.
     * TPM2_import will reject such key with error code TPM_RC_BINDING.
     * Switching to BouncyCastleProvider.
     *
     * @param keySize
     * @param exponent
     * @return
     */
    static Crypto.RsaKeyPair createRsaKey(int keySize, int exponent)
    {
        try
        {
            // Default provider is "SunRsaSign", switch to BouncyCastle
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(keySize);
            KeyPair key = keyGen.generateKeyPair();

            RSAPrivateCrtKey priv = (RSAPrivateCrtKey) key.getPrivate();
            RSAPublicKey pub = (RSAPublicKey) key.getPublic();
            Crypto.RsaKeyPair newKey = new Crypto.RsaKeyPair();
            newKey.PublicKey = pub.getModulus();
            newKey.PrivateKey = priv.getPrimeP();
            return newKey;
        }
        catch(Exception e)
        {
            throw new TpmException("Bad alg:", e);
        }
    }
}
