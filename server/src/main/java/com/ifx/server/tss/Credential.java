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
import tss.Tss;
import tss.tpm.*;

public class Credential {

    private TPMT_PUBLIC pubKey;
    private byte[] keyName;
    private byte[] secret;
    private Tss.ActivationCredential credential;

    public Credential(TPMT_PUBLIC pubKey, byte[] keyName, byte[] secret) {
        this.pubKey = pubKey;
        this.keyName = keyName;
        this.secret = secret;
    }

    public Tss.ActivationCredential makeCredential() throws Exception
    {
        /**
         * Generate credential blob
         */
        credential = Tss.createActivationCredential(pubKey, keyName, secret);
        return credential;
    }

    public String txConvoyCredential() throws Exception {
        TPM2B_ID_OBJECT cred = new TPM2B_ID_OBJECT(credential.CredentialBlob);
        return Hex.toHexString(cred.toTpm());
    }

    public String txConvoyEncSecret() throws Exception {
        return Hex.toHexString(credential.Secret);
    }

}
