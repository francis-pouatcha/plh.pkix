package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.cert.X509CertificateHolder;

public class CertAndCertTemplate {

	private final X509CertificateHolder requestedCert;
	private final CertTemplate certTemplate;
	public CertAndCertTemplate(X509CertificateHolder requestedCert,
			CertTemplate certTemplate) {
		super();
		this.requestedCert = requestedCert;
		this.certTemplate = certTemplate;
	}
	public X509CertificateHolder getRequestedCert() {
		return requestedCert;
	}
	public CertTemplate getCertTemplate() {
		return certTemplate;
	}
}
