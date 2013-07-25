package org.adorsys.plh.pkix.core.smime.plooh;

import org.bouncycastle.cert.X509CertificateHolder;

public class EmailInUseException extends Exception {

	private static final long serialVersionUID = -6697569885289633409L;

	private final X509CertificateHolder certificateHolder;
	
	public EmailInUseException(X509CertificateHolder x509CertificateHolder) {
		this.certificateHolder = x509CertificateHolder;
	}

	public X509CertificateHolder getCertificateHolder() {
		return certificateHolder;
	}
}
