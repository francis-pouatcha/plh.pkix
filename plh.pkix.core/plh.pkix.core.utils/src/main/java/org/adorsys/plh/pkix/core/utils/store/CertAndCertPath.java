package org.adorsys.plh.pkix.core.utils.store;

import org.bouncycastle.cert.X509CertificateHolder;

public class CertAndCertPath {

	private final X509CertificateHolder certHolder;
	private final CertPathAndOrigin certPathAndOrigin;
	private final boolean validSignature;
	public CertAndCertPath(X509CertificateHolder certHolder,
			CertPathAndOrigin certPathAndOrigin, boolean validSignature) {
		super();
		this.certHolder = certHolder;
		this.certPathAndOrigin = certPathAndOrigin;
		this.validSignature = validSignature;
	}
	public X509CertificateHolder getCertHolder() {
		return certHolder;
	}
	public CertPathAndOrigin getCertPathAndOrigin() {
		return certPathAndOrigin;
	}
	public boolean isValidSignature() {
		return validSignature;
	}
	
}
