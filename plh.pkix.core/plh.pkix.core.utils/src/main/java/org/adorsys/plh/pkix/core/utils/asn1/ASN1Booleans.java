package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1Booleans extends ASN1Object {

    private ASN1Sequence content;

    private ASN1Booleans(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1Booleans getInstance(Object o)
    {
        if (o instanceof ASN1Booleans)
        {
            return (ASN1Booleans)o;
        }

        if (o != null)
        {
            return new ASN1Booleans(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Booleans(
        ASN1Boolean asn1Boolean)
    {
        content = new DERSequence(asn1Boolean);
    }

    public ASN1Booleans(
    		ASN1Boolean[] asn1Booleans)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < asn1Booleans.length; i++) {
            v.add(asn1Booleans[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1Boolean[] toArray()
    {
    	ASN1Boolean[] result = new ASN1Boolean[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1Boolean.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * CertificateChain ::= SEQUENCE SIZE (1..MAX) OF Certificate
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
