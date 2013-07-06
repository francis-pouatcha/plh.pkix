package org.adorsys.plh.pkix.core.cmp.certann.sender;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class OutgoingCertAnnPostAction extends GenericAction {
	public static final String SEND_OUTCOME="send";

	private final BuilderChecker checker = new BuilderChecker(OutgoingCertAnnPostAction.class);
	public OutgoingCertAnnPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(SEND_OUTCOME, OutgoingCertAnnSendActionProcessor.class);
		setOutcome(SEND_OUTCOME);
	}
}
