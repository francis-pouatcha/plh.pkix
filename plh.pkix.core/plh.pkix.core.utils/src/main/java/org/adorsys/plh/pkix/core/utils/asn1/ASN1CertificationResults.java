package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1CertificationResults extends ASN1Object {

    private ASN1Sequence content;

    private ASN1CertificationResults(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1CertificationResults getInstance(Object o)
    {
        if (o instanceof ASN1CertificationResults)
        {
            return (ASN1CertificationResults)o;
        }

        if (o != null)
        {
            return new ASN1CertificationResults(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertificationResults(
    		ASN1CertificationResult certificationResult)
    {
        content = new DERSequence(certificationResult);
    }

    public ASN1CertificationResults(
    		ASN1CertificationResult[] certificationResults)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < certificationResults.length; i++) {
            v.add(certificationResults[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1CertificationResult[] toResultArray()
    {
    	ASN1CertificationResult[] result = new ASN1CertificationResult[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1CertificationResult.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * ASN1CertificationResults ::= SEQUENCE SIZE (1..MAX) OF ASN1CertificationResult
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }

	@SuppressWarnings("unused")
	private final ASN1Sequence getContent() {
		return content;
	}
	@SuppressWarnings("unused")
	private final void setContent(ASN1Sequence content) {
		this.content = content;
	}
}
