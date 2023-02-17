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
import tss.*;
import tss.tpm.*;

abstract class Duplicate {

    public Tss.Key key; // original key
    public Tss.DuplicationBlob duplicate; // duplication of the key, ready for convoy
    public byte[] innerWrapperKey;

    public Duplicate() throws Exception {
    }

    abstract void genKey() throws Exception;

    abstract void rxConvoySignature(String data, String signature) throws Exception;

    abstract boolean verify() throws Exception;

    public String txConvoyEncryptedSeed() throws Exception {
        return Hex.toHexString(duplicate.EncryptedSeed);
    }

    public String txConvoyDuplicate() throws Exception {
        return Hex.toHexString(duplicate.DuplicateObject);
    }

    public String txConvoyDuplicatePub() throws Exception {
        TPM2B_PUBLIC pub = new TPM2B_PUBLIC(key.PublicPart);
        return Hex.toHexString(pub.toTpm());
    }

    public String exportPub() throws Exception {
        return txConvoyDuplicatePub();
    }

    public void importPub(String pub) throws Exception {
        TPM2B_PUBLIC pk = TPM2B_PUBLIC.fromTpm(Hex.decode(pub));
        if (key == null)
            key = new Tss.Key();
        key.PublicPart = pk.publicArea;
    }

    /**
     * - Clone of Microsoft Tss.createDuplicationBlob()
     * - Bug fix
     * - Allow assignment of innerWrapperKey
     *
     * @param targetParent
     * @param _publicPart
     * @param _sensitivePart
     * @param innerWrapper
     * @return
     */
    public Tss.DuplicationBlob createDuplicationBlob(
            TPMT_PUBLIC targetParent,
            TPMT_PUBLIC _publicPart,
            TPMT_SENSITIVE _sensitivePart,
            TPMT_SYM_DEF_OBJECT innerWrapper)
    {
        if(!(targetParent.parameters instanceof TPMS_RSA_PARMS))
        {
            throw new TpmException("Only import of keys to RSA storage parents supported");
        }
        TPM_ALG_ID nameAlg = targetParent.nameAlg;

        Tss.DuplicationBlob blob = new Tss.DuplicationBlob();
        byte[] encryptedSensitive = null;
        byte[] nullVec = new byte[0];

        if (innerWrapper.algorithm == TPM_ALG_ID.NULL)
        {
            encryptedSensitive = Helpers.byteArrayToLenPrependedByteArray(_sensitivePart.toTpm());
            blob.EncryptionKey = nullVec;
        } else
        {
            if (innerWrapper.algorithm != TPM_ALG_ID.AES &&
                    innerWrapper.mode != TPM_ALG_ID.CFB)
            {
                throw new TpmException("innerWrapper KeyDef is not supported for import");
            }

            byte[] sens = Helpers.byteArrayToLenPrependedByteArray(_sensitivePart.toTpm());
            byte[]  toHash = Helpers.concatenate(sens, _publicPart.getName());

            byte[] innerIntegrity = Helpers.byteArrayToLenPrependedByteArray(Crypto.hash(_publicPart.nameAlg, toHash));
            byte[] innerData = Helpers.concatenate(innerIntegrity, sens);

            int aesKeyLen = innerWrapper.keyBits/8;
            if (innerWrapperKey == null) {
                innerWrapperKey = Helpers.getRandom(aesKeyLen);
            }
            encryptedSensitive = Crypto.cfbEncrypt(true,TPM_ALG_ID.AES,innerWrapperKey,nullVec,innerData);
            blob.EncryptionKey = innerWrapperKey;
        }

        TPMS_RSA_PARMS newParentParms = (TPMS_RSA_PARMS)(targetParent.parameters);
        TPMT_SYM_DEF_OBJECT newParentSymDef = newParentParms.symmetric;

        if (newParentSymDef.algorithm != TPM_ALG_ID.AES &&
                newParentSymDef.mode != TPM_ALG_ID.CFB)
        {
            throw new TpmException("new parent symmetric key is not supported for import");
        }

        int newParentSymmKeyLen = newParentSymDef.keyBits;
        // Otherwise we know we are AES128
        byte[] seed = Helpers.getRandom(newParentSymmKeyLen/8);
        byte[] encryptedSeed = targetParent.encrypt(seed, "DUPLICATE");

        byte[] symmKey = Crypto.KDFa(targetParent.nameAlg,seed,"STORAGE",_publicPart.getName(),nullVec,newParentSymmKeyLen);

        byte[] dupSensitive = Crypto.cfbEncrypt(true,TPM_ALG_ID.AES,symmKey,nullVec,encryptedSensitive);

        int npNameNumBits = Crypto.digestSize(nameAlg) * 8;
        byte[] hmacKey = Crypto.KDFa(nameAlg, seed, "INTEGRITY", nullVec, nullVec, npNameNumBits);
        byte[] outerDataToHmac = Helpers.concatenate(dupSensitive, _publicPart.getName());
        byte[] outerHmacBytes = Crypto.hmac(nameAlg, hmacKey, outerDataToHmac);
        byte[] outerHmac = Helpers.byteArrayToLenPrependedByteArray(outerHmacBytes);
        byte[] DuplicationBlob = Helpers.concatenate(outerHmac, dupSensitive);

        blob.DuplicateObject = DuplicationBlob;
        blob.EncryptedSeed = encryptedSeed;
        blob.InnerWrapperKey = innerWrapperKey;

        return blob;
    }
}
