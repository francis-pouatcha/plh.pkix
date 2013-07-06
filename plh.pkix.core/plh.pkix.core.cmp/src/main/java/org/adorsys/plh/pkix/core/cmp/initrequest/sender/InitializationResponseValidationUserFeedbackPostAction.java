package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class InitializationResponseValidationUserFeedbackPostAction extends GenericAction {
	public static final String ACCEPT_OUTCOME="accept";

	private final BuilderChecker checker = new BuilderChecker(InitializationResponseValidationUserFeedbackPostAction.class);
	public InitializationResponseValidationUserFeedbackPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(ACCEPT_OUTCOME, InitializationResponseAcceptActionPreProcessor.class);
		setOutcome(ACCEPT_OUTCOME);
	}
}
