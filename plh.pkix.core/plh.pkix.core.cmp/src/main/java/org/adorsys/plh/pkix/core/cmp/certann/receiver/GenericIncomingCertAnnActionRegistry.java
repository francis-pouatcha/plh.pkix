package org.adorsys.plh.pkix.core.cmp.certann.receiver;

import java.util.Arrays;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.bouncycastle.asn1.DERIA5String;

public class GenericIncomingCertAnnActionRegistry {

	private static final BuilderChecker checker = new BuilderChecker(GenericIncomingCertAnnActionRegistry.class);
	public static void executeAction(CMPRequest cmpRequest, ActionContext context){
		checker.checkNull(cmpRequest,context);
		
		IncomingRequests requestOut = context.get(IncomingRequests.class);
		ActionHandler actionHandler = context.get(ActionHandler.class);
		checker.checkNull(requestOut,actionHandler);
		
		ASN1Action nextAction = requestOut.loadAction(cmpRequest);
		if(nextAction==null) return;
		context.put(CMPRequest.class, cmpRequest);

		DERIA5String actionType = nextAction.getActionType();
		String actionKlassName = actionType.getString();
		if(IncomingCertAnnValidationPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new IncomingCertAnnValidationPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		}
	}
}
