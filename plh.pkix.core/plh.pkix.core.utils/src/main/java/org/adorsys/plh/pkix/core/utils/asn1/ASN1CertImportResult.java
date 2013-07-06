package org.adorsys.plh.pkix.core.utils.asn1;

import java.security.cert.CertPath;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.store.ValidationResult;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;

public class ASN1CertImportResult extends ASN1Object {

	private Certificate certificate;
	private ASN1OctetString transactionID;
	private DERGeneralizedTime created;
	
	// Optional
	private ASN1MessageBundles errors;
	private ASN1MessageBundles notifications;

    private ASN1CertImportResult(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        certificate = Certificate.getInstance(en.nextElement());
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
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static ASN1CertImportResult getInstance(Object o)
    {
        if (o instanceof ASN1CertImportResult)
        {
            return (ASN1CertImportResult)o;
        }

        if (o != null)
        {
            return new ASN1CertImportResult(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertImportResult(Certificate certificate,
    		ASN1OctetString transactionID)
    {
    	this(certificate, transactionID, new DERGeneralizedTime(new Date()));
    }

    public ASN1CertImportResult(Certificate certificate,
    		ASN1OctetString transactionID, DERGeneralizedTime created)
    {
    	this.certificate = certificate;
    	this.transactionID = transactionID;
        this.created= created;
    }

    public ASN1CertImportResult(X509CertificateHolder certificateHolder,
    		ASN1OctetString transactionID, Boolean validSignature, CertPath certPath, 
    		List<Boolean> userProvidedFlags, ASN1MessageBundles errors, ASN1MessageBundles notifications)
    {
    	this.certificate = V3CertificateUtils.getX509BCCertificate(certificateHolder);
    	this.transactionID = transactionID;
        this.created= new DERGeneralizedTime(new Date());
        this.errors = errors;
        this.notifications = notifications;
   }
    
    public ASN1CertImportResult(ValidationResult validationResult){
    	this(validationResult.getReturnValue(), validationResult.getTransactionID(),validationResult.isValidSignature(),validationResult.getCertPath(),
    			validationResult.getUserProvidedCerts(), validationResult.getASN1Errors(), validationResult.getASN1Notifications());
    }

	/**
     * <pre>
     * ASN1CertValidationResult ::= SEQUENCE {
     * 					certificate			Certificate
     * 					transactionID		ASN1OctetString
     *                  created	 	  		DERGeneralizedTime,
     *                  notifications  	[0] ASN1MessageBundles OPTIONAL,
     *                  errors  		[1] ASN1MessageBundles OPTIONAL,
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(certificate);
        v.add(transactionID);
        v.add(created);

        addOptional(v, 0, notifications);
        addOptional(v, 1, errors);

        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	public ASN1MessageBundles getErrors() {
		return errors;
	}

	public void setErrors(ASN1MessageBundles errors) {
		this.errors = errors;
	}

	public ASN1MessageBundles getNotifications() {
		return notifications;
	}

	public void setNotifications(ASN1MessageBundles notifications) {
		this.notifications = notifications;
	}

	public Certificate getCertificate() {
		return certificate;
	}

	public ASN1OctetString getTransactionID() {
		return transactionID;
	}

	public DERGeneralizedTime getCreated() {
		return created;
	}

	public boolean hasErrors(){
		if(errors==null) return false;
		ASN1MessageBundle[] messageArray = errors.toMessageArray();
		return  messageArray!=null && messageArray.length>0;
	}
	
	public boolean hasNotifications(){
		if(notifications==null) return false;
		ASN1MessageBundle[] messageArray = notifications.toMessageArray();
		return  messageArray!=null && messageArray.length>0;
	}
}
