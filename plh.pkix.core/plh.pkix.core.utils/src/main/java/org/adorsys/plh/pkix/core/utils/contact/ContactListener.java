package org.adorsys.plh.pkix.core.utils.contact;

import org.bouncycastle.cert.X509CertificateHolder;

public interface ContactListener {
	public void contactAdded(X509CertificateHolder certHolder);
	public void issuedCertificateImported(X509CertificateHolder certHolder);
}
