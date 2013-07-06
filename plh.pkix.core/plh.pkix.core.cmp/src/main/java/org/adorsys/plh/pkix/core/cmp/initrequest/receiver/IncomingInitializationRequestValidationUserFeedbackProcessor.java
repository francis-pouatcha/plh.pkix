package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

public class IncomingInitializationRequestValidationUserFeedbackProcessor implements ActionProcessor{
	private final BuilderChecker checker = new BuilderChecker(IncomingInitializationRequestValidationUserFeedbackProcessor.class);

	@Override
	public void process(ActionContext actionContext) {
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		IncomingRequests requests = actionContext.get(IncomingRequests.class);
		checker.checkNull(cmpRequest,requests);

		ASN1Action nextAction = new ASN1Action(
			cmpRequest.getTransactionID(), 
			new DERGeneralizedTime(new Date()), 
			UUIDUtils.newUUIDasASN1OctetString(), 
			new DERIA5String(IncomingInitializationRequestValidationUserFeedbackPostAction.class.getName()));

		byte[] actionData = requests.loadActionData(cmpRequest);
		if(actionData==null) return;
		ASN1CertValidationResults asn1CertValidationResults = ASN1CertValidationResults.getInstance(actionData);
		
		requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SUCCESS), nextAction, asn1CertValidationResults);
		GenericIncomingInitializationActionRegistry.executeAction(cmpRequest, actionContext);// execute
	}

}
