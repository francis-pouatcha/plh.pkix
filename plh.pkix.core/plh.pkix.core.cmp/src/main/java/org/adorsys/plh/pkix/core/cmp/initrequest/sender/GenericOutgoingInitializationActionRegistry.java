package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.util.Arrays;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.bouncycastle.asn1.DERIA5String;

public class GenericOutgoingInitializationActionRegistry {

	private static final BuilderChecker checker = new BuilderChecker(GenericOutgoingInitializationActionRegistry.class);
	public static void executeAction(CMPRequest cmpRequest, ActionContext context){
		checker.checkNull(cmpRequest,context);
		
		OutgoingRequests requestOut = context.get(OutgoingRequests.class);
		ActionHandler actionHandler = context.get(ActionHandler.class);
		checker.checkNull(requestOut,actionHandler);
		
		ASN1Action nextAction = requestOut.loadAction(cmpRequest);
		if(nextAction==null) return;
		context.put(CMPRequest.class, cmpRequest);

		DERIA5String actionType = nextAction.getActionType();
		String actionKlassName = actionType.getString();
		if(OutgoingInitializationRequestInitPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new OutgoingInitializationRequestInitPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		} else if (InitializationResponseValidationPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new InitializationResponseValidationPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		} else if (InitializationResponseAcceptPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new InitializationResponseAcceptPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		} else if (InitializationResponseValidationUserFeedbackPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new InitializationResponseValidationUserFeedbackPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		} else if (InitializationResponseAcceptUserFeedbackPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new InitializationResponseAcceptUserFeedbackPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		}
	}
}
