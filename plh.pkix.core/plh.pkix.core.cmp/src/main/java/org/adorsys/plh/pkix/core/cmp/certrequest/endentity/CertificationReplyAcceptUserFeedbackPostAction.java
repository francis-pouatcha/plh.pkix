package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class CertificationReplyAcceptUserFeedbackPostAction extends GenericAction {
	public static final String IMPORT="import";

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyAcceptUserFeedbackPostAction.class);
	public CertificationReplyAcceptUserFeedbackPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(IMPORT, CertificationReplyImportActionProcessor.class);
		setOutcome(IMPORT);
	}
}
