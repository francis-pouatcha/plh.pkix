package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResults;

public class CertificationReplyAcceptPostAction extends GenericAction {
	public static final String IMPORT_OUTCOME="import";
	
	private final BuilderChecker checker = new BuilderChecker(CertificationReplyAcceptPostAction.class);
	public CertificationReplyAcceptPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(IMPORT_OUTCOME, CertificationReplyImportActionProcessor.class);
		addProcessor(USER_FEEDBACK_OUTCOME, CertificationReplyAcceptUserFeedbackProcessor.class);
		
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		byte[] actionData = requests.loadActionData(cmpRequest);
		if(actionData == null) return;
		ASN1CertValidationResults certValidationResults = ASN1CertValidationResults.getInstance(actionData);
		
		ASN1CertValidationResult[] certValidationResultArray = certValidationResults.toResultArray();
		for (ASN1CertValidationResult asn1CertValidationResult : certValidationResultArray) {
			if(asn1CertValidationResult==null) continue;
			if(asn1CertValidationResult.hasErrors() || asn1CertValidationResult.hasNotifications()){
				setOutcome(USER_FEEDBACK_OUTCOME);
				return;
			}
		}
		
		setOutcome(IMPORT_OUTCOME);
	}
}
