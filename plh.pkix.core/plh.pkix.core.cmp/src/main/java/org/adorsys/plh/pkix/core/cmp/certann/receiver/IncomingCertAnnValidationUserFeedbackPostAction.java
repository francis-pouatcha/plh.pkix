package org.adorsys.plh.pkix.core.cmp.certann.receiver;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class IncomingCertAnnValidationUserFeedbackPostAction extends GenericAction {
	public static final String IMPORT_OUTCOME="import";

	private final BuilderChecker checker = new BuilderChecker(IncomingCertAnnValidationUserFeedbackPostAction.class);
	public IncomingCertAnnValidationUserFeedbackPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		
		addProcessor(IMPORT_OUTCOME, IncomingCertAnnImportActionProcessor.class);
		setOutcome(IMPORT_OUTCOME);
	}
}
