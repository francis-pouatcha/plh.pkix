package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class IncomingInitializationRequestValidationUserFeedbackPostAction extends GenericAction {
	public static final String RESPONSE_OUTCOME="response";

	private final BuilderChecker checker = new BuilderChecker(IncomingInitializationRequestValidationUserFeedbackPostAction.class);
	public IncomingInitializationRequestValidationUserFeedbackPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		
		addProcessor(RESPONSE_OUTCOME, OutgoingInitializationResponseActionProcessor.class);
		setOutcome(RESPONSE_OUTCOME);
	}
}
