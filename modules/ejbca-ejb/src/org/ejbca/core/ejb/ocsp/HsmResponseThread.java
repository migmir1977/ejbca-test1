/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ocsp;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.keys.util.Ed25519;
import org.cesecore.util.CertTools;

/**
 * This internal class exists for the sole purpose of catching deadlocks in the HSM hardware.
 * 
 * @version $Id$
 */
public class HsmResponseThread implements Callable<BasicOCSPResp> {

    public static final long HSM_TIMEOUT_SECONDS = 30;

    private final BasicOCSPRespBuilder basicRes;
    private final String signingAlgorithm;
    private final PrivateKey signerKey;
    private final JcaX509CertificateHolder[] chain;
    private final String provider;
    private final Date producedAt;
    private String alias;
    private List<OCSPResponseItem> responsesList;
    private RespID respID;
    private Extensions exts;

    public HsmResponseThread(final BasicOCSPRespBuilder basicRes, final String signingAlgorithm, final PrivateKey signerKey,
            final X509Certificate[] chain, final String provider, final Date producedAt) throws OcspFailureException {
        this.basicRes = basicRes;
        this.signingAlgorithm = signingAlgorithm;
        this.signerKey = signerKey;
        this.provider = provider;
        this.producedAt = producedAt;
        try {
            this.chain = CertTools.convertToX509CertificateHolder(chain);
        } catch (CertificateEncodingException e) {
            throw new OcspFailureException(e);
        }
    }

    public HsmResponseThread(final BasicOCSPRespBuilder basicRes, final String signingAlgorithm, final PrivateKey signerKey,
            final X509Certificate[] chain, final String provider, final Date producedAt, String alias, List<OCSPResponseItem> responses, RespID respId, Extensions exts) throws OcspFailureException {
        this.basicRes = basicRes;
        this.signingAlgorithm = signingAlgorithm;
        this.signerKey = signerKey;
        this.provider = provider;
        this.producedAt = producedAt;
        this.alias = alias;
        this.responsesList = responses;
        this.respID = respId;
        this.exts = exts;
        try {
            this.chain = CertTools.convertToX509CertificateHolder(chain);
        } catch (CertificateEncodingException e) {
            throw new OcspFailureException(e);
        }
    }

    @Override
    public BasicOCSPResp call() throws OCSPException {
        try {
            /*
             * BufferingContentSigner defaults to allocating a 4096 bytes buffer. Since a rather large OCSP response (e.g. signed with 4K
             * RSA key, nonce and a one level chain) is less then 2KiB, this is generally a waste of allocation and garbage collection.
             * 
             * In high performance environments, the full OCSP response should in general be smaller than 1492 bytes to fit in a single
             * Ethernet frame.
             * 
             * Lowering this allocation from 20480 to 4096 bytes under ECA-4084 which should still be plenty.
             */

            String lib = null;
            String[] parts = provider.split("-");
            if (parts.length > 1){
                lib = parts[1];
            }

            if(signingAlgorithm.equals("Ed25519") && lib != null && (lib.equals("libcs2_pkcs11.so") || lib.equals("libcs_pkcs11_R2.so"))){

                Iterator it = responsesList.iterator();

                ASN1EncodableVector responses = new ASN1EncodableVector();

                while (it.hasNext())
                {
                    try
                    {
                        OCSPResponseItem item = (OCSPResponseItem) it.next();

                        responses.add( new ResponseObject(item.getCertID(), item.getCertStatus(), item.getThisUpdate(), item.getNextUpdate(), exts ).toResponse());
                    }
                    catch (Exception e)
                    {
                        throw new OCSPException("exception creating Request", e);
                    }
                }


                ResponseData  tbsResp = new ResponseData(respID.toASN1Primitive(), new ASN1GeneralizedTime(producedAt!=null? producedAt : new Date()), new DERSequence(responses), exts);
                DERBitString    bitSig;
                Ed25519 ed = new Ed25519();
                byte[] signature  = ed.sign(alias, tbsResp.getEncoded(ASN1Encoding.DER), provider);

                bitSig = new DERBitString(signature);


                final AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
                
                DERSequence chainSeq = null;

                if (chain != null && chain.length > 0)
                {
                    ASN1EncodableVector v = new ASN1EncodableVector();

                    for (int i = 0; i != chain.length; i++)
                    {
                        v.add(chain[i].toASN1Structure());
                    }

                    chainSeq = new DERSequence(v);
                }

                return new BasicOCSPResp(new BasicOCSPResponse(tbsResp, sigAlgId, bitSig, chainSeq));

    
            }else{
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(signingAlgorithm).setProvider(provider).build(signerKey), 20480);
                return basicRes.build(signer, chain, producedAt!=null? producedAt : new Date());
            }

        } catch (OperatorCreationException | IOException e) {
            throw new OcspFailureException(e);
        }
    }


    private static class ResponseObject
    {
        CertificateID         certId;
        CertStatus            certStatus;
        ASN1GeneralizedTime   thisUpdate;
        ASN1GeneralizedTime   nextUpdate;
        Extensions        extensions;

        public ResponseObject(
            CertificateID     certId,
            CertificateStatus certStatus,
            Date              thisUpdate,
            Date              nextUpdate,
            Extensions    extensions)
        {
            this.certId = certId;

            if (certStatus == null)
            {
                this.certStatus = new CertStatus();
            }
            else if (certStatus instanceof UnknownStatus)
            {
                this.certStatus = new CertStatus(2, DERNull.INSTANCE);
            }
            else
            {
                RevokedStatus rs = (RevokedStatus)certStatus;

                if (rs.hasRevocationReason())
                {
                    this.certStatus = new CertStatus(
                                            new RevokedInfo(new ASN1GeneralizedTime(rs.getRevocationTime()), CRLReason.lookup(rs.getRevocationReason())));
                }
                else
                {
                    this.certStatus = new CertStatus(
                                            new RevokedInfo(new ASN1GeneralizedTime(rs.getRevocationTime()), null));
                }
            }

            this.thisUpdate = new DERGeneralizedTime(thisUpdate);

            if (nextUpdate != null)
            {
                this.nextUpdate = new DERGeneralizedTime(nextUpdate);
            }
            else
            {
                this.nextUpdate = null;
            }

            this.extensions = extensions;
        }

        public SingleResponse toResponse()
            throws Exception
        {
            return new SingleResponse(certId.toASN1Primitive(), certStatus, thisUpdate, nextUpdate, extensions);
        }
    }
}
