package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertChainImportResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertChainImprortResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertImportResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificateChain;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1MessageBundles;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;

public class CertificationReplyImportActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyImportActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		checker.checkNull(actionContext);
		
		ContactManager contactManager = actionContext.get(ContactManager.class);
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		checker.checkNull(cmpRequest,requests, contactManager);
		
		ASN1OctetString transactionID = cmpRequest.getTransactionID();
		
		boolean executeAction = false;
		requests.lock(cmpRequest);
		try {
			byte[] actionData = requests.loadActionData(cmpRequest);
			if(actionData == null) return;

			ASN1CertValidationResults certValidationResults = ASN1CertValidationResults.getInstance(actionData);
			ASN1CertValidationResult[] certValidationResultArray = certValidationResults.toResultArray();

			List<ASN1CertChainImportResult> certChainImportResultList = new ArrayList<ASN1CertChainImportResult>();
			
			for (ASN1CertValidationResult asn1CertValidationResult : certValidationResultArray) {
				if(asn1CertValidationResult==null) continue;
				ASN1CertificateChain certPath = asn1CertValidationResult.getCertPath();
				Certificate[] certArray = certPath.toCertArray();
				List<ASN1CertImportResult> importResults = new ArrayList<ASN1CertImportResult>();
				// import certificate and chain.
				ASN1CertImportResult importResult = null;
				try {
					importResult = new ASN1CertImportResult(certArray[0], transactionID, new DERGeneralizedTime(new Date()));
					importResults.add(importResult);
					contactManager.importIssuedCertificate(certArray);

					// add all ca to the contact db
					for (int i = 1; i < certArray.length; i++) {
						Certificate certificate = certArray[1];
						importResult = new ASN1CertImportResult(certificate, transactionID, new DERGeneralizedTime(new Date()));
						importResults.add(importResult);
						X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(certificate);
						try {
							contactManager.addCertEntry(certificateHolder);
						} catch (PlhCheckedException e) {
							importResult.setErrors(new ASN1MessageBundles(e.getErrorMessage()));
						}
					}
				} catch (PlhCheckedException e) {
					importResult.setErrors(new ASN1MessageBundles(e.getErrorMessage()));
				}
				ASN1CertChainImportResult certChainImportResult = new ASN1CertChainImportResult(importResults.toArray(new ASN1CertImportResult[importResults.size()]));
				
				certChainImportResultList.add(certChainImportResult);
			}

			ASN1CertChainImprortResults certChainImprortResults = new ASN1CertChainImprortResults(certChainImportResultList.toArray(new ASN1CertChainImportResult[certChainImportResultList.size()]));

			ASN1Action nextAction = new ASN1Action(
				cmpRequest.getTransactionID(), 
				new DERGeneralizedTime(new Date()), 
				UUIDUtils.newUUIDasASN1OctetString(), 
				new DERIA5String(CertificationReplyImportPostAction.class.getName()));

			requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SEE_DETAILS), nextAction, certChainImprortResults);
			
			executeAction = true;
		} finally {
			requests.unlock(cmpRequest);
		}
		
		if(executeAction)
			GenericCertRequestActionRegistery.executeAction(cmpRequest, actionContext);// execute
	}
}
