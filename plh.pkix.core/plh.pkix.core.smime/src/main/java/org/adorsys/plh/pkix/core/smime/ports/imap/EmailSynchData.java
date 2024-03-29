package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class EmailSynchData extends ASN1Object {

	/*
	 * This can be used to localize the email account associated with this state object in case
	 * files are tempered on the file system.
	 * 
	 * This information is generated by the {@link EmailAccountData}.
	 */
	private final DERIA5String accountId;
	
	private DERIA5String lasSyncState;
	private DERGeneralizedTime lastSynchDate;
	private ASN1Integer lastProcessedUid;
	private ASN1Integer lastUidValidity;
	private DERGeneralizedTime lastProcessedDate;
	
    private EmailSynchData(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        accountId = DERIA5String.getInstance(en.nextElement());
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
            	lasSyncState = DERIA5String.getInstance(tObj, true);
                break;
            case 1:
            	lastSynchDate = DERGeneralizedTime.getInstance(tObj, true);
                break;
            case 2:
            	lastProcessedUid = ASN1Integer.getInstance(tObj, true);
                break;
            case 3:
            	lastUidValidity = ASN1Integer.getInstance(tObj, true);
                break;
            case 4:
            	lastProcessedDate = DERGeneralizedTime.getInstance(tObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static EmailSynchData getInstance(Object o)
    {
        if (o instanceof EmailSynchData)
        {
            return (EmailSynchData)o;
        }

        if (o != null)
        {
            return new EmailSynchData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public EmailSynchData(DERIA5String accountId)
    {
		assert accountId!=null : "accountId can not be null";
    	this.accountId = accountId;
    }

	/**
     * <pre>
     * ASN1Action ::= SEQUENCE {
     * 					accountId		DERIA5String,
     *                  lasSyncState  		[0] DERIA5String OPTIONAL,
     *                  lastSynchDate  		[1] DERGeneralizedTime OPTIONAL,
     *                  lastProcessedUid  	[2] ASN1Integer OPTIONAL,
     *                  lastUidValidity  	[3] ASN1Integer OPTIONAL,
     *                  lastProcessedDate  	[4] DERGeneralizedTime OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(accountId);

        addOptional(v, 0, lasSyncState);
        addOptional(v, 1, lastSynchDate);
        addOptional(v, 2, lastProcessedUid);
        addOptional(v, 3, lastUidValidity);
        addOptional(v, 4, lastProcessedDate);

        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	public DERIA5String getLasSyncState() {
		return lasSyncState;
	}

	public void setLasSyncState(DERIA5String lasSyncState) {
		this.lasSyncState = lasSyncState;
	}

	public DERGeneralizedTime getLastSynchDate() {
		return lastSynchDate;
	}

	public void setLastSynchDate(DERGeneralizedTime lastSynchDate) {
		this.lastSynchDate = lastSynchDate;
	}

	public DERIA5String getAccountId() {
		return accountId;
	}

	public ASN1Integer getLastProcessedUid() {
		return lastProcessedUid;
	}

	public void setLastProcessedUid(ASN1Integer lastProcessedUid) {
		this.lastProcessedUid = lastProcessedUid;
	}

	public ASN1Integer getLastUidValidity() {
		return lastUidValidity;
	}

	public void setLastUidValidity(ASN1Integer lastUidValidity) {
		this.lastUidValidity = lastUidValidity;
	}

	public DERGeneralizedTime getLastProcessedDate() {
		return lastProcessedDate;
	}

	public void setLastProcessedDate(DERGeneralizedTime lastProcessedDate) {
		this.lastProcessedDate = lastProcessedDate;
	}

}
