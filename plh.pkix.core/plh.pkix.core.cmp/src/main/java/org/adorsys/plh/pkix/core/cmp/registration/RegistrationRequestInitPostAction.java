package org.adorsys.plh.pkix.core.cmp.registration;

import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class RegistrationRequestInitPostAction extends GenericAction {
	public static final String SEND_OUTCOME="send";

	private final BuilderChecker checker = new BuilderChecker(RegistrationRequestInitPostAction.class);
	
	private OutgoingRequests registrationRequests;
	public RegistrationRequestInitPostAction(ActionContext actionContext) {
		
		super(actionContext);
		checker.checkNull(actionContext);
		registrationRequests = actionContext.get(OutgoingRequests.class);
		checker.checkNull(registrationRequests);

		// best case
		addProcessor(SEND_OUTCOME, RegistrationRequestSendActionProcessor.class);

		setOutcome(SEND_OUTCOME);
	}
}
