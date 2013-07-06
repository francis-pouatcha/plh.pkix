package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class InitializationResponseAcceptUserFeedbackPostAction extends GenericAction {
	public static final String IMPORT="import";

	private final BuilderChecker checker = new BuilderChecker(InitializationResponseAcceptUserFeedbackPostAction.class);
	public InitializationResponseAcceptUserFeedbackPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(IMPORT, InitializationResponseImportActionProcessor.class);
		setOutcome(IMPORT);
	}
}
