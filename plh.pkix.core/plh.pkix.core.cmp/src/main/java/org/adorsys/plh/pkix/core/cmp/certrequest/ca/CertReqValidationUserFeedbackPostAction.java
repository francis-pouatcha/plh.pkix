package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class CertReqValidationUserFeedbackPostAction extends GenericAction {
	public static final String APPROVAL_OUTCOME="approval";

	private final BuilderChecker checker = new BuilderChecker(CertReqValidationUserFeedbackPostAction.class);
	public CertReqValidationUserFeedbackPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		
		addProcessor(APPROVAL_OUTCOME, CertReqApprovalActionProcessor.class);
		setOutcome(APPROVAL_OUTCOME);
	}
}
