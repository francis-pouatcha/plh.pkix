package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;

public class InitializationResponseAcceptPostAction extends GenericAction {
	public static final String IMPORT="import";

	private final BuilderChecker checker = new BuilderChecker(InitializationResponseAcceptPostAction.class);
	public InitializationResponseAcceptPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(IMPORT, InitializationResponseImportActionProcessor.class);
		addProcessor(USER_FEEDBACK_OUTCOME, InitializationResponseAcceptUserFeedbackProcessor.class);
		
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		ASN1ProcessingResult processingResult = requests.loadResult(cmpRequest);
		if(processingResult != null) {
			byte[] actionData = requests.loadActionData(cmpRequest);
			if(actionData!=null) {
				
				ASN1CertValidationResults certValidationResults = ASN1CertValidationResults.getInstance(actionData);
				ASN1CertValidationResult[] certValidationResultArray = certValidationResults.toResultArray();
				for (ASN1CertValidationResult asn1CertValidationResult : certValidationResultArray) {
					if(asn1CertValidationResult==null) continue;
					if(asn1CertValidationResult.hasErrors() || asn1CertValidationResult.hasNotifications()){
						setOutcome(USER_FEEDBACK_OUTCOME);
						break;
					}
				}
			}
		
			if(getOutcome()==null)
				if(processingResult.getErrors()!=null || processingResult.getNotifications()!=null) 
					setOutcome(USER_FEEDBACK_OUTCOME);
		}
			
		
		if(getOutcome()==null)
			setOutcome(IMPORT);
	}
}
