package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class ASN1Command extends ASN1Object {
	
	private DERIA5String commandHandle;
	private DERIA5String commandClassName;
	private ASN1ExecutionPlan executionPlan;
	private DERIA5String conditionId;

	
    private ASN1Command(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        commandHandle = DERIA5String.getInstance(en.nextElement());
        commandClassName = DERIA5String.getInstance(en.nextElement());
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
            	executionPlan = ASN1ExecutionPlan.getInstance(tObj);
                break;
            case 1:
            	conditionId = DERIA5String.getInstance(tObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static ASN1Command getInstance(Object o)
    {
        if (o instanceof ASN1Command)
        {
            return (ASN1Command)o;
        }

        if (o != null)
        {
            return new ASN1Command(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Command(DERIA5String commandHandle, DERIA5String commandClassName, ASN1ExecutionPlan executionPlan, DERIA5String conditionId)
    {
    	this.commandHandle = commandHandle;
        this.commandClassName= commandClassName;
        this.executionPlan = executionPlan;
        this.conditionId = conditionId;
    }

	/**
     * <pre>
     * ASN1Action ::= SEQUENCE {
     * 					commandHandle 			DERIA5String,
     * 					commandClassName 		DERIA5String,
     *                  executionPlan  		[0] ASN1ExecutionPlan OPTIONAL,
     *                  conditionId	 		[1] DERIA5String OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(commandHandle);
        v.add(commandClassName);

        addOptional(v, 0, executionPlan);
        addOptional(v, 1, conditionId);

        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	public ASN1ExecutionPlan getExecutionPlan() {
		return executionPlan;
	}

	public void setExecutionPlan(ASN1ExecutionPlan executionPlan) {
		this.executionPlan = executionPlan;
	}

	public DERIA5String getConditionId() {
		return conditionId;
	}

	public void setConditionId(DERIA5String conditionId) {
		this.conditionId = conditionId;
	}

	public DERIA5String getCommandHandle() {
		return commandHandle;
	}

	public DERIA5String getCommandClassName() {
		return commandClassName;
	}
}
