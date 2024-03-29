package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1CertChainImportResult extends ASN1Object {

    private ASN1Sequence content;

    private ASN1CertChainImportResult(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1CertChainImportResult getInstance(Object o)
    {
        if (o instanceof ASN1CertChainImportResult)
        {
            return (ASN1CertChainImportResult)o;
        }

        if (o != null)
        {
            return new ASN1CertChainImportResult(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertChainImportResult(
        ASN1CertImportResult importResult)
    {
        content = new DERSequence(importResult);
    }

    public ASN1CertChainImportResult(
    		ASN1CertImportResult[] importResults)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < importResults.length; i++) {
            v.add(importResults[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1CertImportResult[] toArray()
    {
    	ASN1CertImportResult[] result = new ASN1CertImportResult[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1CertImportResult.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * CertificateChains ::= SEQUENCE SIZE (1..MAX) OF CertificateChain
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
