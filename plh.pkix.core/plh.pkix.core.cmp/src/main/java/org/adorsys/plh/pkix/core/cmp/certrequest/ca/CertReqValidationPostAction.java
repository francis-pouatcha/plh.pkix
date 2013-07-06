package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;

public class CertReqValidationPostAction extends GenericAction {
	public static final String APPROVAL_OUTCOME="approval";

	private final BuilderChecker checker = new BuilderChecker(CertReqValidationPostAction.class);
	public CertReqValidationPostAction(ActionContext actionContext) {

		super(actionContext);
		checker.checkNull(actionContext);
		
		addProcessor(APPROVAL_OUTCOME, CertReqApprovalActionProcessor.class);
		addProcessor(USER_FEEDBACK_OUTCOME, CertReqValidationUserFeedbackProcessor.class);

		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		IncomingRequests requests = actionContext.get(IncomingRequests.class);
		checker.checkNull(cmpRequest);
		
		byte[] actionData = requests.loadActionData(cmpRequest);
		if(actionData!=null) {
			ASN1CertValidationResults certValidationResults = ASN1CertValidationResults.getInstance(actionData);
			ASN1CertValidationResult[] resultArray = certValidationResults.toResultArray();
			for (ASN1CertValidationResult asn1CertValidationResult : resultArray) {
				if(asn1CertValidationResult.hasErrors() || asn1CertValidationResult.hasNotifications()){
					setOutcome(USER_FEEDBACK_OUTCOME);
				}
			}
		}
		if(getOutcome()==null)
			setOutcome(APPROVAL_OUTCOME);
	}
}
