package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertTemplateProcessingResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertTemplateProcessingResults;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

/**
 * This class can process some automatic validation of the requests to be signed.
 * 
 * CertRequestValidationPolicy: We still have to design the class such as to allow for injection of a validation policy that can help
 * reduce the quantity of requests displayed to the user.
 * 
 * For example, the requested signing certificate is in the possession of this signer, policy might decide
 * to automatically delete the request and send no response to the sender. Policy might also decide to
 * automatically send a response to the sender. Policy might also decide to let the user decide what to do.
 * 
 * Possible errors are:
 *    - The requester signing certificate is not in the possession of this signer.
 *    - The cert request violates a cert of constraints defined by the policy.
 * 
 * CertRequestCOmpletionPolicy: This processor might also be injected a policy class that will fill in the 
 * cert template with some additional data before displaying it to the user.
 * 
 * 
 * 
 * 
 * @author francis
 *
 */
public class CertReqApprovalActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertReqApprovalActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		checker.checkNull(actionContext);

		IncomingRequests requests = actionContext.get(IncomingRequests.class);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
				
		checker.checkNull(cmpRequest,requests);
		boolean executeAction = false;
		requests.lock(cmpRequest);
		try {
			PKIMessage pkiMessage = requests.loadRequest(cmpRequest);
			PKIBody pkiBody = pkiMessage.getBody();
			ProtectedPKIMessage protectedPKIMessage=new ProtectedPKIMessage(new GeneralPKIMessage(pkiMessage));
			
			CertReqMessages certReqMessages = CertReqMessages.getInstance(pkiBody.getContent());
			CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
			
			CertRequestValidationPolicy validationPolicy = actionContext.get(CertRequestValidationPolicy.class);
			CertRequestPreProcessor preProcessor = actionContext.get(CertRequestPreProcessor.class);
			List<ASN1CertTemplateProcessingResult> processingResults = new ArrayList<ASN1CertTemplateProcessingResult>(certReqMsgArray.length);
			for (CertReqMsg certReqMsg : certReqMsgArray) {
				CertRequest certReq = certReqMsg.getCertReq();
				CertTemplate certTemplate = certReq.getCertTemplate();
				ASN1Integer certReqId = certReq.getCertReqId();
				ASN1CertTemplateProcessingResult processingResult = new ASN1CertTemplateProcessingResult(certReqId, certTemplate, cmpRequest.getTransactionID());

				if(validationPolicy!=null){
					processingResult = validationPolicy.check(processingResult,protectedPKIMessage);
				}
				
				if(preProcessor!=null){
					processingResult = preProcessor.process(processingResult,protectedPKIMessage);
				}
				processingResults.add(processingResult);
				
			}
			
			ASN1CertTemplateProcessingResults asn1CertTemplateProcessingResults = 
					new ASN1CertTemplateProcessingResults(processingResults.toArray(new ASN1CertTemplateProcessingResult[processingResults.size()]));
			
			
			ASN1Action nextAction = new ASN1Action(
				cmpRequest.getTransactionID(), 
				new DERGeneralizedTime(new Date()), 
				UUIDUtils.newUUIDasASN1OctetString(), 
				new DERIA5String(CertReqApprovalPostAction.class.getName()));

			// Cert template will be null if none of them is contained in the request.
			requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SUCCESS), nextAction, asn1CertTemplateProcessingResults);
			executeAction=true;
		} catch(PlhUncheckedException e){
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
		} finally {
			requests.unlock(cmpRequest);
		}

		if(executeAction)
			GenericCertResponseActionRegistry.executeAction(cmpRequest, actionContext);// execute			
	}
}
