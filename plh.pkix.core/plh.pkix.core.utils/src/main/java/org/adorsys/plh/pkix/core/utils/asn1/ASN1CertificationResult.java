package org.adorsys.plh.pkix.core.utils.asn1;

import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Document the a certification. Will be used to properly produce the certification
 * reply to the requester.
 * 
 * @author fpo
 *
 */
public class ASN1CertificationResult extends ASN1Object {

	private ASN1Integer certReqId;
	private ASN1CertificateChain certificateChain;
	private ASN1OctetString transactionID;
	private DERGeneralizedTime created;

	// Optional
	private ASN1MessageBundles notifications;	
	private ASN1MessageBundles errors;
	private ASN1MessageBundles actions;	

    private ASN1CertificationResult(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        certReqId = ASN1Integer.getInstance(en.nextElement());
        certificateChain = ASN1CertificateChain.getInstance(en.nextElement());
        transactionID = ASN1OctetString.getInstance(en.nextElement());
        created = DERGeneralizedTime.getInstance(en.nextElement());
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
                notifications= ASN1MessageBundles.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 1:
                errors = ASN1MessageBundles.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 3:
                actions = ASN1MessageBundles.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static ASN1CertificationResult getInstance(Object o)
    {
        if (o instanceof ASN1CertificationResult)
        {
            return (ASN1CertificationResult)o;
        }

        if (o != null)
        {
            return new ASN1CertificationResult(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertificationResult(ASN1Integer certReqId, ASN1CertificateChain certificateChain,
    		ASN1OctetString transactionID)
    {
    	this(certReqId, certificateChain, transactionID, new DERGeneralizedTime(new Date()));
    }

    public ASN1CertificationResult(ASN1Integer certReqId, ASN1CertificateChain certificateChain,
    		ASN1OctetString transactionID, DERGeneralizedTime created)
    {
    	this.certReqId = certReqId;
    	this.certificateChain = certificateChain;
    	this.transactionID = transactionID;
        this.created= created;
    }

    public ASN1CertificationResult(ASN1Integer certReqId, ASN1CertificateChain certificateChain,
    		ASN1OctetString transactionID, DERGeneralizedTime created, 
    		ASN1MessageBundles notifications,
    		ASN1MessageBundles errors, 
    		ASN1MessageBundles actions)
    {
    	this(certReqId, certificateChain, transactionID, created);
    	this.notifications = notifications;
        this.errors = errors;
        this.actions = actions;
   }

	/**
     * <pre>
     * ASN1CertificationResult ::= SEQUENCE {
     * 					certReqId				ASN1Integer,
     * 					certificateChain		ASN1CertificateChain,
     * 					transactionID			ASN1OctetString,
     *                  created	 	  			DERGeneralizedTime,
     *                  notifications  		[0] ASN1MessageBundles OPTIONAL,
     *                  errors  			[1] ASN1MessageBundles OPTIONAL,
     *                  actions  			[2] ASN1MessageBundles OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(certReqId);
        v.add(certificateChain);
        v.add(transactionID);
        v.add(created);

        addOptional(v, 0, notifications);
        addOptional(v, 1, errors);
        addOptional(v, 2, actions);

        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	public ASN1Integer getCertReqId() {
		return certReqId;
	}

	public ASN1MessageBundles getNotifications() {
		return notifications;
	}

	public void setNotifications(ASN1MessageBundles notifications) {
		this.notifications = notifications;
	}

	public ASN1CertificateChain getCertificateChain() {
		return certificateChain;
	}


	public ASN1MessageBundles getErrors() {
		return errors;
	}

	public void setErrors(ASN1MessageBundles errors) {
		this.errors = errors;
	}

	public ASN1MessageBundles getActions() {
		return actions;
	}

	public void setActions(ASN1MessageBundles actions) {
		this.actions = actions;
	}
	
	public ASN1OctetString getTransactionID() {
		return transactionID;
	}

	public DERGeneralizedTime getCreated() {
		return created;
	}
	
	public boolean hasNotifications(){
		if(notifications==null) return false;
		ASN1MessageBundle[] messageArray = notifications.toMessageArray();
		return  messageArray!=null && messageArray.length>0;
	}

	public boolean hasErrors(){
		if(errors==null) return false;
		ASN1MessageBundle[] messageArray = errors.toMessageArray();
		return  messageArray!=null && messageArray.length>0;
	}

	public boolean hasActions(){
		if(actions==null) return false;
		ASN1MessageBundle[] messageArray = actions.toMessageArray();
		return  messageArray!=null && messageArray.length>0;
	}
}
