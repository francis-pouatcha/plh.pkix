package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class CertificationRequestInitPostAction extends GenericAction {
	public static final String SEND_OUTCOME="send";

	private final BuilderChecker checker = new BuilderChecker(CertificationRequestInitPostAction.class);
	public CertificationRequestInitPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(SEND_OUTCOME, CertificationRequestSendActionProcessor.class);
		setOutcome(SEND_OUTCOME);
	}
}
