package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

/**
 * Just send to user for feedback. User will check cert template processing result, eventually manually modify cert templates and then
 * initializes creation of certificates. 
 * 
 * @author fpo
 *
 */
public class CertReqApprovalPostAction extends GenericAction {

	private final BuilderChecker checker = new BuilderChecker(CertReqApprovalPostAction.class);
	public CertReqApprovalPostAction(ActionContext actionContext) {
		super(actionContext);
		
		checker.checkNull(actionContext);

		addProcessor(USER_FEEDBACK_OUTCOME, CertReqApprovalUserFeedbackProcessor.class);

		setOutcome(USER_FEEDBACK_OUTCOME);
	}
}
