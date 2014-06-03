package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class SMTPSentMessageData  extends ASN1Object {
	
	private final DERIA5String messageId;
	private final DERGeneralizedTime sent;

	//============================START OPTIONAL FIELDS ================================//
	private DERIA5String status;

	private DERIA5String errorMessgae;

	public SMTPSentMessageData(DERIA5String messageId, DERGeneralizedTime sent) {
		assert messageId!=null : "argument messageId can not be null";
		assert sent!=null : "argument sent can not be null";
		this.messageId = messageId;
		this.sent = sent;
	}
	
    private SMTPSentMessageData(ASN1Sequence seq) {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        messageId = DERIA5String.getInstance(en.nextElement());
        sent = DERGeneralizedTime.getInstance(en.nextElement());
        
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
                status = DERIA5String.getInstance(tObj, true);
                break;
            case 1:
            	errorMessgae = DERIA5String.getInstance(tObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static SMTPSentMessageData getInstance(Object o)
    {
        if (o instanceof SMTPSentMessageData)
        {
            return (SMTPSentMessageData)o;
        }

        if (o != null)
        {
            return new SMTPSentMessageData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

	/**
     * <pre>
     * ASN1Action ::= SEQUENCE {
     * 					messageId				DERIA5String,
     * 					sent					DERGeneralizedTime,
     * 					status					[0] DERIA5String OPTIONAL,
     * 					errorMessgae			[1] DERIA5String OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(messageId);
        v.add(sent);
        addOptional(v,0,status);
        addOptional(v,1,errorMessgae);

        return new DERSequence(v);
	}
    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	public DERIA5String getStatus() {
		return status;
	}

	public void setStatus(DERIA5String status) {
		this.status = status;
	}

	public DERIA5String getErrorMessgae() {
		return errorMessgae;
	}

	public void setErrorMessgae(DERIA5String errorMessgae) {
		this.errorMessgae = errorMessgae;
	}

	public DERIA5String getMessageId() {
		return messageId;
	}

	public DERGeneralizedTime getSent() {
		return sent;
	}
}
