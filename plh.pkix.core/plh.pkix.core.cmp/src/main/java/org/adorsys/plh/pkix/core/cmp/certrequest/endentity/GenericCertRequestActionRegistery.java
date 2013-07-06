package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.util.Arrays;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.bouncycastle.asn1.DERIA5String;

public class GenericCertRequestActionRegistery {

	private static final BuilderChecker checker = new BuilderChecker(GenericCertRequestActionRegistery.class);
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
		if(CertificationRequestInitPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new CertificationRequestInitPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		} else if (CertificationReplyValidationPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new CertificationReplyValidationPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		} else if (CertificationReplyAcceptPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new CertificationReplyAcceptPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		} else if(CertificationReplyImportPostAction.class.getName().equals(actionKlassName)){
			Action postAction = new CertificationReplyImportPostAction(context);
			actionHandler.handle(Arrays.asList(postAction));
		}
	}
}
