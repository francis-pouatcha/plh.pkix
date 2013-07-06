package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertTemplateProcessingResults;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

/**
 * Subclass will let the user decide on how to proceed.
 * 
 * This default implementation does the following:
 * 		- If there is neither error nor notifications, forward to certification process.
 * 		- If requested ca certificate is not under the control of the current signer, delete the request.
 * 		- If requested validity period too long, modify the validity period. 
 * 
 * @author fpo
 *
 */
public class CertReqApprovalUserFeedbackProcessor implements ActionProcessor{
	private final BuilderChecker checker = new BuilderChecker(CertReqApprovalUserFeedbackProcessor.class);

	@Override
	public void process(ActionContext actionContext) {
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		IncomingRequests requests = actionContext.get(IncomingRequests.class);
		checker.checkNull(cmpRequest,requests);

		byte[] actionData = requests.loadActionData(cmpRequest);
		ASN1CertTemplateProcessingResults asn1CertTemplateProcessingResults = 
				ASN1CertTemplateProcessingResults.getInstance(actionData);
				
		ASN1Action nextAction = new ASN1Action(
			cmpRequest.getTransactionID(), 
			new DERGeneralizedTime(new Date()), 
			UUIDUtils.newUUIDasASN1OctetString(), 
			new DERIA5String(CertReqApprovalUserDecision.class.getName()));

		requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SUCCESS), nextAction, asn1CertTemplateProcessingResults);
		GenericCertResponseActionRegistry.executeAction(cmpRequest, actionContext);// execute
	}
}
