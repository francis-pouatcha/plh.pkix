package org.adorsys.plh.pkix.core.smime.ports;

import javax.mail.internet.MimeMessage;

public interface SMIMEMessageEndpoint {

	/**
	 * Receives the next pki message addressed 
	 * to this end entity.
	 * 
	 * @return
	 */
	public void receive(MimeMessage message);
	
}
