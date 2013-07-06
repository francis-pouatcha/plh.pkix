package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.store.PKISignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.ValidationResult;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.i18n.ErrorBundle;

public class CertificationReplyValidationProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyValidationProcessor.class);
	public void process(ActionContext actionContext) {
		checker.checkNull(actionContext);
		
		PKIMessage responseMessage = actionContext.get(PKIMessage.class);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		checker.checkNull(responseMessage,requests, contactManager);

		// store the incoming response
		CMPRequest cmpRequest = requests.loadRequest(responseMessage.getHeader().getTransactionID());
		if(cmpRequest==null){
			// non existing request can not be processed. Ignore.
			return;// no send back
		}
		
		requests.setResponse(cmpRequest, responseMessage);
		
		actionContext.put(CMPRequest.class, cmpRequest);
		
		boolean executeAction = false;
		requests.lock(cmpRequest);
		try {
			PKISignedMessageValidator signedMessageValidator = new PkiMessageChecker().check(responseMessage,contactManager);
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
				new DERIA5String(CertificationReplyValidationPostAction.class.getName()));

			requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SUCCESS), nextAction, asn1CertValidationResults);
			
			executeAction = true;
		} catch(PlhUncheckedException e){
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
		} catch(RuntimeException e){
			ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(e, getClass().getName()+"#process");
			ErrorMessageHelper.processError(cmpRequest, requests, errorMessage);
		} finally {
			requests.unlock(cmpRequest);
		}

		if(executeAction)
			GenericCertRequestActionRegistery.executeAction(cmpRequest, actionContext);// execute
	}
}
