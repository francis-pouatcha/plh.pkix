package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * A sequence of DER utf8 strings
 * 
 * @author fpo
 *
 */
public class DERUTF8Strings extends ASN1Object {

    private ASN1Sequence content;

    private DERUTF8Strings(ASN1Sequence seq)
    {
        content = seq;
    }

    public static DERUTF8Strings getInstance(Object o)
    {
        if (o instanceof DERUTF8Strings)
        {
            return (DERUTF8Strings)o;
        }

        if (o != null)
        {
            return new DERUTF8Strings(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public DERUTF8Strings(
        DERUTF8String string)
    {
        content = new DERSequence(string);
    }

    public DERUTF8Strings(
    		DERUTF8String[] strings)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < strings.length; i++) {
            v.add(strings[i]);
        }
        content = new DERSequence(v);
    }

    public DERUTF8String[] toValueArray()
    {
    	DERUTF8String[] result = new DERUTF8String[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = DERUTF8String.getInstance(content.getObjectAt(i));
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
