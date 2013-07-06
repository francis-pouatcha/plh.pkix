package org.adorsys.plh.pkix.core.cmp.stores;

import java.util.Date;
import java.util.Enumeration;

import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;

public class CMPRequest extends ASN1Object {

	// Mandatory
	private ASN1OctetString transactionID;
	private DERGeneralizedTime created;
	private DERIA5String status;
	// this is supposed to be the type field in the body field "type" of the main message.
	private ASN1Integer messageType;
	// identifies the process instance in the business logic realm.
	private DERUTF8String workflowId;
	
	// The id of the next action
	private ASN1OctetString nextActionId;
	
	private ASN1OctetString requestId;
	private ASN1OctetString responseId;

	private ASN1OctetString lastPollRepId;
	private ASN1OctetString lastPollReqId;
	
	private DERGeneralizedTime lastResult;

	private DERGeneralizedTime disposed;

    private CMPRequest(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        transactionID = ASN1OctetString.getInstance(en.nextElement());
        created= DERGeneralizedTime.getInstance(en.nextElement());
        status = DERIA5String.getInstance(en.nextElement());
        messageType = ASN1Integer.getInstance(en.nextElement());
        workflowId = DERUTF8String.getInstance(en.nextElement());
        
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
                nextActionId = ASN1OctetString.getInstance(tObj, true);
                break;
            case 1:
                disposed = DERGeneralizedTime.getInstance(tObj, true);
                break;
            case 2:
            	requestId = ASN1OctetString.getInstance(tObj, true);
                break;
            case 3:
            	responseId = ASN1OctetString.getInstance(tObj, true);
                break;
            case 4:
            	lastPollRepId = ASN1OctetString.getInstance(tObj, true);
                break;
            case 5:
            	lastPollReqId = ASN1OctetString.getInstance(tObj, true);
                break;
            case 6:
            	lastResult = DERGeneralizedTime.getInstance(tObj, true);
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static CMPRequest getInstance(Object o)
    {
        if (o instanceof CMPRequest)
        {
            return (CMPRequest)o;
        }

        if (o != null)
        {
            return new CMPRequest(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public CMPRequest(ASN1OctetString transactionID,
    		DERGeneralizedTime created, ASN1Integer messageType, DERUTF8String workflowId)
    {
    	this.transactionID = transactionID;
        this.created = created;
        this.status = new DERIA5String(ProcessingStatus.UNKNOWN);
        this.messageType = messageType;
        this.workflowId = workflowId;
    }

    public CMPRequest(ASN1Integer messageType, DERUTF8String workflowId)
    {
    	this.transactionID = UUIDUtils.newUUIDasASN1OctetString();
        this.created = new DERGeneralizedTime(new Date());
        this.status = new DERIA5String(ProcessingStatus.UNKNOWN);
        this.messageType = messageType;
        this.workflowId = workflowId;
    }

	/**
     * <pre>
     * PendingRequestData ::= SEQUENCE {
     * 					transactionID			ASN1OctetString
     *                  created        			DERGeneralizedTime,
     *                  status  				DERIA5String,
     *                  messageType  			ASN1Integer,
     *                  workflowId  			DERUTF8String,
     *                  nextActionId  		[0] ASN1Action OPTIONAL,
     *                  disposed   			[1] DERGeneralizedTime OPTIONAL,
     *                  requestId 			[2] PKIMessage OPTIONAL,
     *                  responseId 			[3] PKIMessage OPTIONAL,
     *                  lastPollReqId  		[4] PKIMessage OPTIONAL
     *                  lastPollRepId  		[5] PKIMessage OPTIONAL,
     *                  lastResultId	 	[6] ASN1ProcessingResults OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(transactionID);
        v.add(created);
        v.add(status);
        v.add(messageType);
        v.add(workflowId);

        addOptional(v, 0, nextActionId);
        addOptional(v, 1, disposed);
        addOptional(v, 2, requestId);
        addOptional(v, 3, responseId);
        addOptional(v, 4, lastPollReqId);
        addOptional(v, 5, lastPollRepId);
        addOptional(v, 6, lastResult);

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

	public ASN1Integer getMessageType() {
		return messageType;
	}

	public DERUTF8String getWorkflowId() {
		return workflowId;
	}

	public ASN1OctetString getNextActionId() {
		return nextActionId;
	}

	void setNextActionId(ASN1OctetString nextActionId) {
		this.nextActionId = nextActionId;
	}

	public ASN1OctetString getRequestId() {
		return requestId;
	}

	void setRequestId(ASN1OctetString requestId) {
		this.requestId = requestId;
	}

	public ASN1OctetString getResponseId() {
		return responseId;
	}

	void setResponseId(ASN1OctetString responseId) {
		this.responseId = responseId;
	}

	public ASN1OctetString getLastPollRepId() {
		return lastPollRepId;
	}

	void setLastPollRepId(ASN1OctetString lastPollRepId) {
		this.lastPollRepId = lastPollRepId;
	}

	public ASN1OctetString getLastPollReqId() {
		return lastPollReqId;
	}

	void setLastPollReqId(ASN1OctetString lastPollReqId) {
		this.lastPollReqId = lastPollReqId;
	}

	public DERGeneralizedTime getLastResult() {
		return lastResult;
	}

	void setLastResult(DERGeneralizedTime lastResult) {
		this.lastResult = lastResult;
	}

	public DERGeneralizedTime getDisposed() {
		return disposed;
	}

	public void setDisposed(DERGeneralizedTime disposed) {
		this.disposed = disposed;
	}

	public ASN1OctetString getTransactionID() {
		return transactionID;
	}

	public DERGeneralizedTime getCreated() {
		return created;
	}
}
