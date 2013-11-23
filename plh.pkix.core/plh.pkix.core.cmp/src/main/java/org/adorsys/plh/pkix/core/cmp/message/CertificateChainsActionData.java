package org.adorsys.plh.pkix.core.cmp.message;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificateChains;

/**
 * We can use a key store to store a list of certificates.
 * 
 * @author francis
 *
 */
public class CertificateChainsActionData implements ActionData {
	
	private ASN1CertificateChains certificateChains;

	public CertificateChainsActionData(ASN1CertificateChains certificateChains) {
		this.certificateChains = certificateChains;
	}

	public ASN1CertificateChains getCertificateChains() {
		return certificateChains;
	}

	public void setCertificateChains(ASN1CertificateChains certificateChains) {
		this.certificateChains = certificateChains;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(certificateChains, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		byte[] bs = ASN1StreamUtils.readFrom(inputStream);
		certificateChains = ASN1CertificateChains.getInstance(bs);
	}
}
