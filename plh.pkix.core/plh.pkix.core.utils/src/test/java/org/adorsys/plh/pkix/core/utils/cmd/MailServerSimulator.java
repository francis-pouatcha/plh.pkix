package org.adorsys.plh.pkix.core.utils.cmd;

import javax.mail.MessagingException;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

public class MailServerSimulator {
	private boolean available;
	
	public MailServerSimulator(ActionContext commandContext){
		commandContext.put(MailServerSimulator.class, this);
	}
	
	public String receiveMessage(String o) throws MessagingException {
		try {
			Thread.currentThread().sleep(1000);
		} catch (InterruptedException e) {
			// noop
		}
		if(!available) throw new MessagingException("Server down");
		try {
			Thread.currentThread().sleep(1000);
		} catch (InterruptedException e) {
			// noop
		}
		return o;
	}

	public boolean isAvailable() {
		return available;
	}

	public void setAvailable(boolean available) {
		this.available = available;
	}
	
	
}
