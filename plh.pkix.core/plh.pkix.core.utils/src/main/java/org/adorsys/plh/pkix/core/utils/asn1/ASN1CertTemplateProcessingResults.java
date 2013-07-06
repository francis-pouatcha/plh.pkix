package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1CertTemplateProcessingResults extends ASN1Object {

    private ASN1Sequence content;

    private ASN1CertTemplateProcessingResults(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1CertTemplateProcessingResults getInstance(Object o)
    {
        if (o instanceof ASN1CertTemplateProcessingResults)
        {
            return (ASN1CertTemplateProcessingResults)o;
        }

        if (o != null)
        {
            return new ASN1CertTemplateProcessingResults(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertTemplateProcessingResults(
        ASN1CertTemplateProcessingResult processingResult)
    {
        content = new DERSequence(processingResult);
    }

    public ASN1CertTemplateProcessingResults(
    		ASN1CertTemplateProcessingResult[] processingResults)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < processingResults.length; i++) {
            v.add(processingResults[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1CertTemplateProcessingResult[] toResultArray()
    {
    	ASN1CertTemplateProcessingResult[] result = new ASN1CertTemplateProcessingResult[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1CertTemplateProcessingResult.getInstance(content.getObjectAt(i));
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
