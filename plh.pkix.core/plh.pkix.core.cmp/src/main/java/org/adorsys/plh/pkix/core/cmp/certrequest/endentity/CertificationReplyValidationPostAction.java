package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;

public class CertificationReplyValidationPostAction extends GenericAction {
	public static final String ACCEPT_OUTCOME="accept";

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyValidationPostAction.class);
	public CertificationReplyValidationPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(ACCEPT_OUTCOME, CertificationReplyAcceptActionPreProcessor.class);
		addProcessor(USER_FEEDBACK_OUTCOME, CertificationReplyValidationUserFeedbackProcessor.class);

		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		byte[] actionData = requests.loadActionData(cmpRequest);
		if(actionData==null) return;
		ASN1CertValidationResults certValidationResults = ASN1CertValidationResults.getInstance(actionData);
		ASN1CertValidationResult[] resultArray = certValidationResults.toResultArray();
		
		if(resultArray==null || resultArray.length<=0) return;
		
		for (ASN1CertValidationResult certValidationResult : resultArray) {
			if(certValidationResult.hasErrors() || certValidationResult.hasNotifications() || !certValidationResult.isValidSignature()){
				setOutcome(USER_FEEDBACK_OUTCOME);			
				break;
			}				
		}
		if(getOutcome()==null)
			setOutcome(ACCEPT_OUTCOME);// suspect all good.
	}
}
