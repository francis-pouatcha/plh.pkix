package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class CertificationReplyValidationUserFeedbackPostAction extends GenericAction {
	public static final String ACCEPT_OUTCOME="accept";

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyValidationUserFeedbackPostAction.class);
	public CertificationReplyValidationUserFeedbackPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(ACCEPT_OUTCOME, CertificationReplyAcceptActionPreProcessor.class);
		setOutcome(ACCEPT_OUTCOME);
	}
}
