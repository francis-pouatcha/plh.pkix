package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.store.PKISignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.ValidationResult;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class CertReqValidationProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertReqValidationProcessor.class);
	public void process(ActionContext actionContext) {

		checker.checkNull(actionContext);
		
		PKIMessage requestMessage = actionContext.get(PKIMessage.class);
		UserAccount userAccount = actionContext.get(UserAccount.class);
		IncomingRequests requests = actionContext.get(IncomingRequests.class);
		checker.checkNull(requestMessage,requests, userAccount);

		// store the incoming response
		ASN1OctetString transactionID = requestMessage.getHeader().getTransactionID();

		// the same initialization message can not be sent twice. Ignorw the message.
		CMPRequest cmpRequest = requests.loadRequest(transactionID);
		if(cmpRequest!=null)
			return;// no send back
		
		cmpRequest = new CMPRequest(transactionID, new DERGeneralizedTime(new Date()), 
				new ASN1Integer(PKIBody.TYPE_CERT_REQ), new DERUTF8String(KeyIdUtils.hexEncode(transactionID)));
		requests.newRequest(cmpRequest);
		requests.setRequest(cmpRequest, requestMessage);
		
		actionContext.put(CMPRequest.class, cmpRequest);
		
		boolean executeAction = false;
		requests.lock(cmpRequest);
		try {
			PKISignedMessageValidator signedMessageValidator = new PkiMessageChecker().check(requestMessage,userAccount.getTrustedContactManager());
			List<ValidationResult> results = signedMessageValidator.getResults();
			List<ASN1CertValidationResult> certValidationResults = new ArrayList<ASN1CertValidationResult>();
			for (ValidationResult validationResult : results) {
				certValidationResults.add(new ASN1CertValidationResult(validationResult));
			}
			ASN1CertValidationResults asn1CertValidationResults = new ASN1CertValidationResults(certValidationResults.toArray(new ASN1CertValidationResult[certValidationResults.size()]));

			ASN1Action nextAction = new ASN1Action(
				cmpRequest.getTransactionID(), 
				new DERGeneralizedTime(new Date()), 
				UUIDUtils.newUUIDasASN1OctetString(), 
				new DERIA5String(CertReqValidationPostAction.class.getName()));

			requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SUCCESS), nextAction, asn1CertValidationResults);
			
			executeAction = true;
		} catch(PlhUncheckedException e){
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
//		} catch(RuntimeException e){
//			ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(e, getClass().getName()+"#process");
//			ErrorMessageHelper.processError(cmpRequest, requests, errorMessage);
		} finally {
			requests.unlock(cmpRequest);
		}
		
		if(executeAction)
			GenericCertResponseActionRegistry.executeAction(cmpRequest, actionContext);// execute
	}
}
