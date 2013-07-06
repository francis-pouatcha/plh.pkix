package org.adorsys.plh.pkix.core.utils.asn1;

import java.security.cert.CertPath;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.store.ValidationResult;
import org.bouncycastle.asn1.ASN1Boolean;
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

public class ASN1CertValidationResult extends ASN1Object {

	private Certificate certificate;
	private ASN1OctetString transactionID;
	private DERGeneralizedTime created;
	
	private ASN1Boolean validSignature;
	
	// Optional
	private ASN1MessageBundles errors;
	private ASN1MessageBundles notifications;
	
	private ASN1CertificateChain certPath;
	private ASN1Booleans userSuppliedFlags;
	

    private ASN1CertValidationResult(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        certificate = Certificate.getInstance(en.nextElement());
        transactionID = ASN1OctetString.getInstance(en.nextElement());
        created = DERGeneralizedTime.getInstance(en.nextElement());
        validSignature = ASN1Boolean.getInstance(en.nextElement());
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
            case 2:
            	certPath = ASN1CertificateChain.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 3:
                userSuppliedFlags = ASN1Booleans.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static ASN1CertValidationResult getInstance(Object o)
    {
        if (o instanceof ASN1CertValidationResult)
        {
            return (ASN1CertValidationResult)o;
        }

        if (o != null)
        {
            return new ASN1CertValidationResult(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertValidationResult(Certificate certificate,
    		ASN1OctetString transactionID, ASN1Boolean validSignature)
    {
    	this(certificate, transactionID, new DERGeneralizedTime(new Date()), validSignature);
    }

    public ASN1CertValidationResult(Certificate certificate,
    		ASN1OctetString transactionID, DERGeneralizedTime created, ASN1Boolean validSignature)
    {
    	this.certificate = certificate;
    	this.transactionID = transactionID;
        this.created= created;
        this.validSignature = validSignature;
    }

    public ASN1CertValidationResult(X509CertificateHolder certificateHolder,
    		ASN1OctetString transactionID, Boolean validSignature, CertPath certPath, 
    		List<Boolean> userProvidedFlags, ASN1MessageBundles errors, ASN1MessageBundles notifications)
    {
    	this.certificate = V3CertificateUtils.getX509BCCertificate(certificateHolder);
    	this.transactionID = transactionID;
        this.created= new DERGeneralizedTime(new Date());
        this.errors = errors;
        this.notifications = notifications;

    	Boolean[] booleans = userProvidedFlags.toArray(new Boolean[userProvidedFlags.size()]);
    	ASN1Boolean[] b = new ASN1Boolean[userProvidedFlags.size()];
    	for (int i = 0; i < booleans.length; i++) {
    		b[i]=new ASN1Boolean(booleans[i]);
		}
    	userSuppliedFlags = new ASN1Booleans(b);

    	List<? extends java.security.cert.Certificate> certificates = certPath.getCertificates();
    	java.security.cert.Certificate[] certificatesArray = certificates.toArray(new java.security.cert.Certificate[certificates.size()]);
    	Certificate[] crts = new Certificate[certificates.size()];
    	for (int i = 0; i < certificatesArray.length; i++) {
    		crts[i] = V3CertificateUtils.getX509BCCertificate(certificatesArray[i]);
		}
		this.certPath = new ASN1CertificateChain(crts);
		
		this.validSignature = new ASN1Boolean(validSignature);
   }
    
    public ASN1CertValidationResult(ValidationResult validationResult){
    	this(validationResult.getReturnValue(), validationResult.getTransactionID(),validationResult.isValidSignature(),validationResult.getCertPath(),
    			validationResult.getUserProvidedCerts(), validationResult.getASN1Errors(), validationResult.getASN1Notifications());
    }

	/**
     * <pre>
     * ASN1CertValidationResult ::= SEQUENCE {
     * 					certificate				Certificate
     * 					transactionID			ASN1OctetString
     *                  created	 	  			DERGeneralizedTime,
     *                  validSignature			ASN1Boolean,
     *                  notifications  		[0] ASN1MessageBundles OPTIONAL,
     *                  errors  			[1] ASN1MessageBundles OPTIONAL,
     *                  certPath			[2]	ASN1CertificateChain,
     *                  userSuppliedFlags	[3]	ASN1Booleans
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
        v.add(validSignature);

        addOptional(v, 0, notifications);
        addOptional(v, 1, errors);
        addOptional(v, 2, certPath);
        addOptional(v, 3, userSuppliedFlags);

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

	public ASN1Boolean getValidSignature() {
		return validSignature;
	}

	public ASN1CertificateChain getCertPath() {
		return certPath;
	}

	public ASN1Booleans getUserSuppliedFlags() {
		return userSuppliedFlags;
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
	
	public boolean isValidSignature(){
		if(validSignature==null) return false;
		return validSignature.isTrue();
	}

	public void setCertPath(ASN1CertificateChain certPath) {
		this.certPath = certPath;
	}

	public void setUserSuppliedFlags(ASN1Booleans userSuppliedFlags) {
		this.userSuppliedFlags = userSuppliedFlags;
	}
}
