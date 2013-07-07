package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.store.CertAndCertPath;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

/**
 * Prepares and invoke the {@link CertificationReplyAcceptActionExecutor}. Forwards control
 * to the {@link ActionHandler} in the context in case of error.
 * @author francis
 *
 */
public class CertificationReplyAcceptActionPreProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyAcceptActionPreProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		checker.checkNull(actionContext);
		
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		checker.checkNull(cmpRequest,requests);
		
		boolean executeAction = false;
		requests.lock(cmpRequest);
		try {
			 List<ProcessingResults<CertAndCertPath>> processingResultsList = new CertificationReplyAcceptActionExecutor()
					.withActionContext(actionContext)
					.execute();
			 List<ASN1CertValidationResult> certValidationResults = new ArrayList<ASN1CertValidationResult>();

			 // iterate
			 for (ProcessingResults<CertAndCertPath> processingResults : processingResultsList) {
				 CertAndCertPath certAndCertPath = processingResults.getReturnValue();
					
				 ASN1CertValidationResult asn1CertValidationResult = new ASN1CertValidationResult(certAndCertPath.getCertHolder(),
						 cmpRequest.getTransactionID(),certAndCertPath.isValidSignature(), 
						 certAndCertPath.getCertPathAndOrigin().getCertPath(), certAndCertPath.getCertPathAndOrigin().getUserProvidedFlags(),
						 processingResults.getASN1Errors(), processingResults.getASN1Notifications());						
				 certValidationResults.add(asn1CertValidationResult);
			 }

			ASN1CertValidationResults asn1CertValidationResults = new ASN1CertValidationResults(certValidationResults.toArray(new ASN1CertValidationResult[certValidationResults.size()]));

			ASN1Action nextAction = new ASN1Action(
				cmpRequest.getTransactionID(), 
				new DERGeneralizedTime(new Date()), 
				UUIDUtils.newUUIDasASN1OctetString(), 
				new DERIA5String(CertificationReplyAcceptPostAction.class.getName()));

			requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SUCCESS), nextAction, asn1CertValidationResults);
			
			executeAction = true;
		} catch(PlhUncheckedException e){
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
		} finally {
			requests.unlock(cmpRequest);
		} 
		
		if(executeAction)
			GenericCertRequestActionRegistery.executeAction(cmpRequest, actionContext);// execute
			
	}
}
