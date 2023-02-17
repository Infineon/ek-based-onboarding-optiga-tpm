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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.encoders.Hex;
import tss.Crypto;
import tss.TpmException;
import tss.Tss;
import tss.tpm.*;

import java.util.Arrays;

public class DuplicateHMAC extends Duplicate {

    private static final TPM_ALG_ID algId = TPM_ALG_ID.SHA256;
    public byte[] seed;
    private byte[] data;
    private byte[] signature;
    private static final TPMT_SYM_DEF_OBJECT NullSymDef = new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL,  0, TPM_ALG_ID.NULL);
    private static final TPMT_PUBLIC template = new TPMT_PUBLIC(
            // TPMI_ALG_HASH nameAlg
            algId,
            // TPMA_OBJECT  objectAttributes
            new TPMA_OBJECT(TPMA_OBJECT.sign, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.noDA),
            // TPM2B_DIGEST authPolicy
            new byte[0],
            // TPMU_PUBLIC_PARMS    parameters
            new TPMS_KEYEDHASH_PARMS(new TPMS_SCHEME_HMAC(algId)),
            // TPMU_PUBLIC_ID       unique
            new TPM2B_DIGEST_Keyedhash(new byte[0]));

    public DuplicateHMAC() throws Exception {
        super();
    }

    public void genKey() throws Exception {
        key = createKey(template);
    }

    public void rxConvoySignature(String data, String signature) throws Exception {
        this.data = Hex.decode(data);
        this.signature = Hex.decode(signature);
    }

    public String exportPriv() throws Exception {
        return Hex.toHexString(key.PrivatePart);
    }

    public void importPriv(String priv) throws Exception {
        if (key == null)
            key = new Tss.Key();
        key.PrivatePart = Hex.decode(priv);
    }

    public byte[] sign(byte[] data) throws Exception {
        return Crypto.hmac(key.PublicPart.nameAlg, key.PrivatePart, data);
    }

    public boolean verify() throws Exception {
        byte[] sig = Crypto.hmac(key.PublicPart.nameAlg, key.PrivatePart, data);
        return Arrays.equals(signature, sig);
    }

    public void duplicate(TPMT_PUBLIC parentPub) throws Exception {
        byte[] swKeyAuthValue = new byte[] {0};

        TPMT_SENSITIVE sens = new TPMT_SENSITIVE(swKeyAuthValue, seed, new TPM2B_SENSITIVE_DATA(key.PrivatePart));
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
     * Clone of Microsoft Tss.createKey() with additional algorithm support
     *
     * @param pub
     * @return
     */
    private Tss.Key createKey(TPMT_PUBLIC pub) throws Exception {
        Tss.Key tssKey = new Tss.Key();

        if(pub.GetUnionSelector_parameters()== TPM_ALG_ID.KEYEDHASH.toInt())
        {
            int size = Crypto.digestSize(algId);
            byte[] secret = Utils.getRandom(size);
            byte[] digest = new byte[size];
            seed = Utils.getRandom(size); // obfuscation value for the unique field

            // calculate the unique field, algorithm is decided by the nameAlg
            Digest d = Crypto.getDigest(algId);
            d.update(seed, 0, seed.length);
            d.update(secret, 0, secret.length);
            d.doFinal(digest, 0);

            tssKey.PublicPart = new TPMT_PUBLIC(pub.nameAlg, pub.objectAttributes, pub.authPolicy, pub.parameters,
                    new TPM2B_DIGEST_Keyedhash(digest));
            tssKey.PrivatePart = secret;

        }
        else
            throw new TpmException("Unsupported alg");
        return tssKey;
    }

}
