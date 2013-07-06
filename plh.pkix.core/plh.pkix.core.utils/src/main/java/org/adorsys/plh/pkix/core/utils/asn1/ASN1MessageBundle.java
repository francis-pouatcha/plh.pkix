package org.adorsys.plh.pkix.core.utils.asn1;

import java.util.Date;
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
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.i18n.MessageBundle;

public class ASN1MessageBundle extends ASN1Object {

	private DERIA5String id;
	private DERIA5String resource;
	
	private DERGeneralizedTime created;
	
	// optional sequence of utf8 strings
	private DERUTF8Strings args;

	private ASN1MessageBundle(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();
        
        resource = DERIA5String.getInstance(en.nextElement());
        id=DERIA5String.getInstance(en.nextElement());
        created= DERGeneralizedTime.getInstance(en.nextElement());
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
            	args= DERUTF8Strings.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static ASN1MessageBundle getInstance(Object o)
    {
        if (o instanceof ASN1MessageBundle)
        {
            return (ASN1MessageBundle)o;
        }

        if (o != null)
        {
            return new ASN1MessageBundle(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1MessageBundle(
    		DERIA5String resource,
    		DERIA5String id)
    {
    	this.resource = resource;
    	this.id=id;
        this.created=new DERGeneralizedTime(new Date());
    }
    public ASN1MessageBundle(
    		DERIA5String resource,
    		DERIA5String id, DERUTF8String[] args)
    {
    	this.resource = resource;
    	this.id=id;
        this.created=new DERGeneralizedTime(new Date());
        this.args = new DERUTF8Strings(args);
    }
    public ASN1MessageBundle(
    		String resource,
    		String id, String...args)
    {
    	this.resource = new DERIA5String(resource);
    	this.id=new DERIA5String(id);
        this.created=new DERGeneralizedTime(new Date());
        DERUTF8String[] arguments = new DERUTF8String[args.length];
        for (int i = 0; i < args.length; i++) {
        	arguments[i]=new DERUTF8String(args[i]);
		}
        this.args = new DERUTF8Strings(arguments);
    }
    
    public ASN1MessageBundle(MessageBundle messageBundle){
    	this.resource = new DERIA5String(messageBundle.getResource());
    	this.id = new DERIA5String(messageBundle.getId());
        this.created=new DERGeneralizedTime(new Date());
        Object[] args = messageBundle.getArguments();
        if(args!=null && args.length>0){
	        DERUTF8String[] arguments = new DERUTF8String[args.length];
	        for (int i = 0; i < args.length; i++) {
	        	arguments[i]=args[i]==null?new DERUTF8String(""):new DERUTF8String(args[i].toString());			
			}
	        this.args = new DERUTF8Strings(arguments);
        }
    }

	/**
     * <pre>
     * ASN1MessageBundle ::= SEQUENCE {
     * 					resource	DERIAS5String,
     * 					id			DERIAS5String,
     *                  created     DERGeneralizedTime,
     *                  args  	[0] DERUTF8Strings OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(resource);
        v.add(id);
        v.add(created);

        addOptional(v, 0, args);
        
        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	public DERIA5String getId() {
		return id;
	}

	public DERIA5String getResource() {
		return resource;
	}

	public DERGeneralizedTime getCreated() {
		return created;
	}
	
	public ErrorBundle toErrorBundle(){
		if(args!=null){
			DERUTF8String[] valueArray = args.toValueArray();
			Object[] arguments = new Object[valueArray.length];
			for (int i = 0; i < valueArray.length; i++) {
				arguments[i] = valueArray[i]==null?"":valueArray[i].toString();
			}
			return new ErrorBundle(resource.getString(), id.getString(), arguments);
		}
		return new ErrorBundle(resource.getString(), id.getString());
	}
}
