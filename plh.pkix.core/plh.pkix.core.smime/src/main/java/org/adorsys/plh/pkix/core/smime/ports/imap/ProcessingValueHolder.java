package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.Date;

public class ProcessingValueHolder {

	private Date d;
	
	private Long l;
	
	public void process(Date dateIn, Long uidIn){
		if(d==null || d.before(dateIn))d=dateIn;
		if(l==null || l<uidIn)l=uidIn;
	}

	public Date getD() {
		return d;
	}

	public Long getL() {
		return l;
	}

}
