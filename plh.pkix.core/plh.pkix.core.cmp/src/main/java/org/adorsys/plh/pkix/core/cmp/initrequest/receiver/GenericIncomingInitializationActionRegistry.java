package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import java.util.Arrays;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.bouncycastle.asn1.DERIA5String;

public class GenericIncomingInitializationActionRegistry {

	private static final BuilderChecker checker = new BuilderChecker(GenericIncomingInitializationActionRegistry.class);
	public static void executeAction(CMPRequest cmpRequest, ActionContext context){
		checker.checkNull(cmpRequest,context);
		
		IncomingRequests requestIn = context.get(IncomingRequests.class);
		ActionHandler actionHandler = context.get(ActionHandler.class);
		checker.checkNull(requestIn,actionHandler);
		
		ASN1Action nextAction = requestIn.loadAction(cmpRequest);
		if(nextAction==null) return;
		context.put(CMPRequest.class, cmpRequest);

		DERIA5String actionType = nextAction.getActionType();
		String actionKlassName = actionType.getString();
		if(IncomingInitializationRequestValidationPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new IncomingInitializationRequestValidationPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		} else if (OutgoingInitializationResponsePostAction.class.getName().equals(actionKlassName)){
			Action postAction = new OutgoingInitializationResponsePostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		} else if (IncomingInitializationRequestValidationUserFeedbackPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new IncomingInitializationRequestValidationUserFeedbackPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		}
	}
}
