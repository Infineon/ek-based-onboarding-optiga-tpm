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

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import tss.Crypto;
import tss.Tss;
import tss.tpm.*;
import java.math.BigInteger;
import java.security.*;

import static com.ifx.server.tss.Utils.toBigInteger;

public class DuplicateECC extends Duplicate {

    private byte[] data;
    private TPMU_SIGNATURE signature;
    private static final TPMT_PUBLIC template = new TPMT_PUBLIC(
            // TPMI_ALG_HASH nameAlg
            TPM_ALG_ID.SHA256,
            // TPMA_OBJECT  objectAttributes
            new TPMA_OBJECT(TPMA_OBJECT.sign, TPMA_OBJECT.sensitiveDataOrigin, TPMA_OBJECT.userWithAuth),
            // TPM2B_DIGEST authPolicy
            new byte[0],
            // TPMU_PUBLIC_PARMS    parameters
            new TPMS_ECC_PARMS(new TPMT_SYM_DEF_OBJECT().nullObject(),
                    new TPMS_SIG_SCHEME_ECDSA(TPM_ALG_ID.SHA256),
                    TPM_ECC_CURVE.NIST_P256,
                    new TPMS_NULL_KDF_SCHEME()),
            // TPMU_PUBLIC_ID       unique
            new TPMS_ECC_POINT());

    public DuplicateECC() throws Exception {
        super();
    }

    public void genKey() throws Exception {
        key = Tss.createKey(template);
    }

    public void rxConvoySignature(String data, String signature) throws Exception {
        this.data = Hex.decode(data);
        TPMU_SIGNATURE sig = TPMS_SIGNATURE_ECDSA.fromTpm(Hex.decode(signature));
        this.signature = sig;
    }

    public boolean verify() throws Exception {
        TPMS_ECC_POINT pub = (TPMS_ECC_POINT)key.PublicPart.unique;
        TPMS_ECC_PARMS param = (TPMS_ECC_PARMS)key.PublicPart.parameters;
        TPMS_SIG_SCHEME_ECDSA scheme = (TPMS_SIG_SCHEME_ECDSA)param.scheme;
        TPM_ALG_ID hashAlg = scheme.hashAlg;
        TPMS_SIGNATURE_ECDSA sig = ((TPMS_SIGNATURE_ECDSA)signature);

        X9ECParameters ecParams = NISTNamedCurves.getByName("P-256");
        ECPoint pubPoint = ecParams.getCurve().createPoint(toBigInteger(pub.x), toBigInteger(pub.y));
        ECDomainParameters parameters = new ECDomainParameters(ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());

        ECDSASigner signer = new ECDSASigner();
        signer.init(false, new ECPublicKeyParameters(pubPoint, parameters));

        return signer.verifySignature(Crypto.hash(hashAlg, data), toBigInteger(sig.signatureR), toBigInteger(sig.signatureS));

        // Too bad this will not work, not fully implemented in Microsoft library
        //return key.PublicPart.validateSignature(data, signature);
    }

    public void duplicate(TPMT_PUBLIC parentPub) throws Exception {
        byte[] swKeyAuthValue = new byte[] {0};
        TPMT_SENSITIVE sens = new TPMT_SENSITIVE(swKeyAuthValue, new byte[0], new TPM2B_ECC_PARAMETER(key.PrivatePart));
        duplicate = createDuplicationBlob(parentPub, key.PublicPart, sens,
                new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES,  128, TPM_ALG_ID.CFB));
        // dupBlob.EncryptionKey == dupBlob.InnerWrapperKey // A key use to encrypt duplicate object as first layer encryption
        // dupBlob.EncryptedSeed; // A seed encrypted by parent key (srk); seed to derive a key for second layer encryption of duplicate object
        // dupBlob.DuplicateObject; // Encrypted key object to migrate
    }

    private PublicKey generatePublicKey(byte[] x, byte[] y) throws Exception {
        X9ECParameters ecParams = NISTNamedCurves.getByName("secp256k1");
        ECPoint pPublicPoint = ecParams.getCurve().createPoint(new BigInteger(x), new BigInteger(y));
        ECParameterSpec spec = new ECParameterSpec(ecParams.getCurve(),
                ecParams.getG(), ecParams.getN());
        ECPublicKeySpec publicSpec = new ECPublicKeySpec(pPublicPoint, spec);
        KeyFactory keyfac = KeyFactory.getInstance("ECDSA", "LOCAL_BC");
        return keyfac.generatePublic(publicSpec);
    }
}
