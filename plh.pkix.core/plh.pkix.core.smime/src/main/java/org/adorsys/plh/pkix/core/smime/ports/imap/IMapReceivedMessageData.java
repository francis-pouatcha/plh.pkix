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
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class IMapReceivedMessageData  extends ASN1Object {
	
	private final DERIA5String messageId;
	private final DERInteger messageUid;
	private final DERInteger uidValidity;
	
	private final DERGeneralizedTime received;

	//============================START OPTIONAL FIELDS ================================//
	private DERIA5String status;

	private DERIA5String errorMessgae;

	public IMapReceivedMessageData(DERIA5String messageId, DERInteger messageUid, DERInteger uidValidity, DERGeneralizedTime received) {
		assert messageId!=null : "argument messageId can not be null";
		assert messageUid!=null : "argument messageUid can not be null";
		assert received!=null : "argument received can not be null";
		this.messageId = messageId;
		this.messageUid = messageUid;
		this.uidValidity = uidValidity;
		this.received = received;
	}
	
    private IMapReceivedMessageData(ASN1Sequence seq) {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        messageId = DERIA5String.getInstance(en.nextElement());
        messageUid = DERInteger.getInstance(en.nextElement());
        uidValidity = DERInteger.getInstance(en.nextElement());
        received = DERGeneralizedTime.getInstance(en.nextElement());
        
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

    public static IMapReceivedMessageData getInstance(Object o)
    {
        if (o instanceof IMapReceivedMessageData)
        {
            return (IMapReceivedMessageData)o;
        }

        if (o != null)
        {
            return new IMapReceivedMessageData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

	/**
     * <pre>
     * ASN1Action ::= SEQUENCE {
     * 					messageId				DERIA5String,
     * 					messageUid				DERInteger,
     * 					uidValidity				DERInteger,
     * 					received				DERGeneralizedTime,
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
        v.add(messageUid);
        v.add(uidValidity);
        v.add(received);
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

	public DERGeneralizedTime getReceived() {
		return received;
	}

	public DERInteger getMessageUid() {
		return messageUid;
	}

	public DERInteger getUidValidity() {
		return uidValidity;
	}
}
