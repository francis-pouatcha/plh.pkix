package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;

public class CertReqCertifyPostAction extends GenericAction {

	public static final String RESPOND_OUTCOME="respond";

	private final BuilderChecker checker = new BuilderChecker(CertReqCertifyPostAction.class);
	public CertReqCertifyPostAction(ActionContext actionContext) {

		super(actionContext);
		checker.checkNull(actionContext);
		
		addProcessor(RESPOND_OUTCOME, CertReqResponseActionProcessor.class);

		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		checker.checkNull(cmpRequest);
		
		if(getOutcome()==null)
			setOutcome(RESPOND_OUTCOME);
	}
}
