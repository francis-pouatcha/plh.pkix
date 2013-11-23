package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;

/**
 * Defines the execution plan for this command.
 * 
 * @author fpo
 *
 */
public class ASN1ExecutionPlan extends ASN1Object {

	private DERGeneralizedTime executionTime;
	private ASN1Integer fixRate;
	private DERIA5String timeUnit;

    private ASN1ExecutionPlan(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        executionTime = DERGeneralizedTime.getInstance(en.nextElement());
        fixRate = ASN1Integer.getInstance(en.nextElement());
        timeUnit = DERIA5String.getInstance(en.nextElement());
    }

    public static ASN1ExecutionPlan getInstance(Object o)
    {
        if (o instanceof ASN1ExecutionPlan)
        {
            return (ASN1ExecutionPlan)o;
        }

        if (o != null)
        {
            return new ASN1ExecutionPlan(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1ExecutionPlan(DERGeneralizedTime executionTime,ASN1Integer fixRate,DERIA5String timeUnit)
    {
    	this.executionTime = executionTime;
        this.fixRate= fixRate;
        this.timeUnit = timeUnit;
    }

	/**
     * <pre>
     * ASN1Action ::= SEQUENCE {
     *                  executionTime	 	DERGeneralizedTime,
     * 					fixRate 			ASN1Integer,
     * 					timeUnit 			DERIA5String
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(executionTime);
        v.add(fixRate);
        v.add(timeUnit);

        return new DERSequence(v);
	}

	public DERGeneralizedTime getExecutionTime() {
		return executionTime;
	}

	public ASN1Integer getFixRate() {
		return fixRate;
	}

	public DERIA5String getTimeUnit() {
		return timeUnit;
	}
	
}
