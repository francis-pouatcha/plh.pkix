package org.adorsys.plh.pkix.core.smime.plooh;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Holds a certificate and the preferred mail address for a mail.
 * 
 * @author fpo
 *
 */
public class EmailRecipient {
	
	private final X509CertificateHolder certificateHolder;
	
	private final String preferredEmail;

	public EmailRecipient(X509CertificateHolder certificateHolder,
			String preferredEmail) {
		super();
		this.certificateHolder = certificateHolder;
		this.preferredEmail = preferredEmail;
	}

	public X509CertificateHolder getCertificateHolder() {
		return certificateHolder;
	}

	public String getPreferredEmail() {
		return preferredEmail;
	}
}
