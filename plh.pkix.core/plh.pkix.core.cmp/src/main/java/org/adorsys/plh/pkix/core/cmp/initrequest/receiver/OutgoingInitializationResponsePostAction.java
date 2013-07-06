package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;

public class OutgoingInitializationResponsePostAction extends GenericAction {
	public static final String SEND_OUTCOME="send";
	
	private final BuilderChecker checker = new BuilderChecker(OutgoingInitializationResponsePostAction.class);
	public OutgoingInitializationResponsePostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		// best case
		addProcessor(SEND_OUTCOME, OutgoingInitializationResponseSendActionProcessor.class);
		// error, park request for user feedback.
		addProcessor(USER_FEEDBACK_OUTCOME, OutgoingInitializationResponseUserFeedbackProcessor.class);

		IncomingRequests requests = actionContext.get(IncomingRequests.class);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		
		ASN1ProcessingResult processingResult = requests.loadResult(cmpRequest);
		if(processingResult!=null && (processingResult.getErrors()!=null || processingResult.getNotifications()!=null)){
			setOutcome(USER_FEEDBACK_OUTCOME);
		}
		
		if(getOutcome()==null)
			setOutcome(SEND_OUTCOME);
	}
}
