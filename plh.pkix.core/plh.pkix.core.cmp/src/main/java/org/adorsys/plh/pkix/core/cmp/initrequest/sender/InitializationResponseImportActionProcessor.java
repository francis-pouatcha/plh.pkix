package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificateChain;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;

public class InitializationResponseImportActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(InitializationResponseImportActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		checker.checkNull(actionContext);
		
		ContactManager contactManager = actionContext.get(ContactManager.class);
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		checker.checkNull(cmpRequest,requests, contactManager);
		
		requests.lock(cmpRequest);
		try {

			byte[] actionDataBytes = requests.loadActionData(cmpRequest);
			if(actionDataBytes==null) return;
			
			ASN1CertValidationResults certValidationResults = ASN1CertValidationResults.getInstance(actionDataBytes);
			ASN1CertValidationResult[] certValidationResultArray = certValidationResults.toResultArray();

			ProcessingResults<CMPRequest> processingResults = new ProcessingResults<CMPRequest>();
			for (ASN1CertValidationResult asn1CertValidationResult : certValidationResultArray) {
				if(asn1CertValidationResult==null) continue;
				ASN1CertificateChain certPath = asn1CertValidationResult.getCertPath();
				Certificate[] certArray = certPath.toCertArray();
				for (Certificate certificate : certArray) {
					X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(certificate);
					try {
						contactManager.addCertEntry(certificateHolder);
					} catch (PlhCheckedException e) {
						processingResults.addError(e.getErrorMessage());
					}
				}
			}
			if(processingResults.hasError()){
				ErrorMessageHelper.processError(cmpRequest, requests, processingResults);
			} else {
				requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SUCCESS), null, null);
			}
		} finally {
			requests.unlock(cmpRequest);
		}
	}
}
