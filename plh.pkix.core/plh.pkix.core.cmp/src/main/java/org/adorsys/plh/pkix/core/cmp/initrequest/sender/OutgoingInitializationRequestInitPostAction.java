package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class OutgoingInitializationRequestInitPostAction extends GenericAction {
	public static final String SEND_OUTCOME="send";
	
	private final BuilderChecker checker = new BuilderChecker(OutgoingInitializationRequestInitPostAction.class);
	public OutgoingInitializationRequestInitPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(SEND_OUTCOME, OutgoingInitializationRequestSendActionProcessor.class);
		setOutcome(SEND_OUTCOME);
	}
}
