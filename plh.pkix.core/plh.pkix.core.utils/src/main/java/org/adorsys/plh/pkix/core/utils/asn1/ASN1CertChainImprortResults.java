package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1CertChainImprortResults extends ASN1Object {

    private ASN1Sequence content;

    private ASN1CertChainImprortResults(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1CertChainImprortResults getInstance(Object o)
    {
        if (o instanceof ASN1CertChainImprortResults)
        {
            return (ASN1CertChainImprortResults)o;
        }

        if (o != null)
        {
            return new ASN1CertChainImprortResults(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertChainImprortResults(
        ASN1CertChainImportResult importResult)
    {
        content = new DERSequence(importResult);
    }

    public ASN1CertChainImprortResults(
    		ASN1CertChainImportResult[] importResults)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < importResults.length; i++) {
            v.add(importResults[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1CertChainImportResult[] toArray()
    {
    	ASN1CertChainImportResult[] result = new ASN1CertChainImportResult[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1CertChainImportResult.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * ASN1CertChainImportResults ::= SEQUENCE SIZE (1..MAX) OF ASN1CertChainImportResult
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
