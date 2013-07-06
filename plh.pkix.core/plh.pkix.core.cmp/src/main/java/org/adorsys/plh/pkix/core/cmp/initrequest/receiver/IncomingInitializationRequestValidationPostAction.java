package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;

public class IncomingInitializationRequestValidationPostAction extends GenericAction {
	public static final String RESPONSE_OUTCOME="response";

	private final BuilderChecker checker = new BuilderChecker(IncomingInitializationRequestValidationPostAction.class);
	public IncomingInitializationRequestValidationPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		
		addProcessor(RESPONSE_OUTCOME, OutgoingInitializationResponseActionProcessor.class);
		addProcessor(USER_FEEDBACK_OUTCOME, IncomingInitializationRequestValidationUserFeedbackProcessor.class);

		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		IncomingRequests requests = actionContext.get(IncomingRequests.class);
		checker.checkNull(cmpRequest,requests);
		
		ASN1ProcessingResult processingResult = requests.loadResult(cmpRequest);
		if((processingResult!=null) && (processingResult.getErrors()!=null || processingResult.getNotifications()!=null)){
			setOutcome(USER_FEEDBACK_OUTCOME);
			return;
		}		
		
		byte[] actionData = requests.loadActionData(cmpRequest);
		if(actionData==null) return;
		
		ASN1CertValidationResults certValidationResults = ASN1CertValidationResults.getInstance(actionData);
		ASN1CertValidationResult[] resultArray = certValidationResults.toResultArray();
		for (ASN1CertValidationResult asn1CertValidationResult : resultArray) {
			if(asn1CertValidationResult.hasErrors() || asn1CertValidationResult.hasNotifications()){
				setOutcome(USER_FEEDBACK_OUTCOME);
				break;
			}
		}
		
		if(getOutcome()==null)
			setOutcome(RESPONSE_OUTCOME);
	}
}
