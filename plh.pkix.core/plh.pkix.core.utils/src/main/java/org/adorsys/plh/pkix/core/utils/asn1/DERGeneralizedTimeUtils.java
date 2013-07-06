package org.adorsys.plh.pkix.core.utils.asn1;

import java.text.ParseException;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.DERGeneralizedTime;

public class DERGeneralizedTimeUtils {

	public static Date getDate(DERGeneralizedTime time){
		if(time==null)return null;
		try {
			return time.getDate();
		} catch (ParseException e) {
			throw PlhUncheckedException.toException(e, DERGeneralizedTimeUtils.class);
		}
	}
}
