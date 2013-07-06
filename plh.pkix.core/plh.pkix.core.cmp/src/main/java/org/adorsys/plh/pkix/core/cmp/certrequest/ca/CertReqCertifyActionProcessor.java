package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertTemplateProcessingResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertTemplateProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificateChain;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificationResults;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.i18n.ErrorBundle;

public class CertReqCertifyActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertReqValidationProcessor.class);

	@Override
	public void process(ActionContext actionContext) {

		checker.checkNull(actionContext);
		
		IncomingRequests requests = actionContext.get(IncomingRequests.class);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		
		checker.checkNull(requests, cmpRequest);
		boolean executeAction = false;
		requests.lock(cmpRequest);
		try {
			byte[] actionData = requests.loadActionData(cmpRequest);
			if(actionData==null) return;
			
			ASN1CertTemplateProcessingResults asn1CertTemplateProcessingResults = 
					ASN1CertTemplateProcessingResults.getInstance(actionData);
			ASN1CertTemplateProcessingResult[] resultArray = asn1CertTemplateProcessingResults.toResultArray();
			ASN1CertificationResult[] certificationResultArray = new ASN1CertificationResult[resultArray.length];
			for (int i = 0; i < resultArray.length; i++) {
				ASN1CertTemplateProcessingResult asn1CertTemplateProcessingResult = resultArray[i];
				CertTemplate certTemplate = asn1CertTemplateProcessingResult.getCertTemplate();
				// invoke action executor
				ASN1CertificateChain certificateChain = new CertReqCertifyActionExecutor()
						.withCertTemplate(certTemplate).execute(actionContext);
				ASN1CertificationResult certificationResult = new ASN1CertificationResult(asn1CertTemplateProcessingResult.getCertReqId(),
						certificateChain, 
						asn1CertTemplateProcessingResult.getTransactionID(), new DERGeneralizedTime(new Date()), 
						asn1CertTemplateProcessingResult.getNotifications(), 
						asn1CertTemplateProcessingResult.getErrors(), 
						asn1CertTemplateProcessingResult.getActions());
				certificationResultArray[i] = certificationResult;
			}
			ASN1CertificationResults certificationResults = new ASN1CertificationResults(certificationResultArray);

			ASN1Action nextAction = new ASN1Action(
				cmpRequest.getTransactionID(), 
				new DERGeneralizedTime(new Date()), 
				UUIDUtils.newUUIDasASN1OctetString(), 
				new DERIA5String(CertReqCertifyPostAction.class.getName()));
			
			requests.setResultAndNextAction(cmpRequest, null, 
					new DERIA5String(ProcessingStatus.SUCCESS), nextAction, certificationResults);
			executeAction=true;
		} catch(PlhUncheckedException e){
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
		} catch(RuntimeException e){
			ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(e, getClass().getName()+"#process");
			ErrorMessageHelper.processError(cmpRequest, requests, errorMessage);
		} finally {
			requests.unlock(cmpRequest);
		}
		
		if(executeAction)
			GenericCertResponseActionRegistry.executeAction(cmpRequest, actionContext);// execute
	}
}
