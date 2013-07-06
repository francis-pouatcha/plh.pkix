package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertTemplateProcessingResult;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

public class CertRequestValidationPolicy {

	public ASN1CertTemplateProcessingResult check(ASN1CertTemplateProcessingResult processingResult,
			ProtectedPKIMessage protectedPKIMessage) {
		return processingResult;
	}
}
