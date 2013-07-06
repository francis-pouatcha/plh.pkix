package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import org.adorsys.plh.pkix.core.cmp.certann.sender.OutgoingCertAnnActionProcessor;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertChainImportResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertChainImprortResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertImportResult;

public class CertificationReplyImportPostAction extends GenericAction {
	public static final String ANNOUNCE_OUTCOME="announce";

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyImportPostAction.class);
	public CertificationReplyImportPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		addProcessor(ANNOUNCE_OUTCOME, OutgoingCertAnnActionProcessor.class);
		addProcessor(USER_FEEDBACK_OUTCOME, CertificationReplyImportUserFeedbackProcessor.class);
		
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		byte[] actionData = requests.loadActionData(cmpRequest);
		if(actionData==null) return;
		ASN1CertChainImprortResults certChainImprortResults = ASN1CertChainImprortResults.getInstance(actionData);
		ASN1CertChainImportResult[] certChainImprortResultArray = certChainImprortResults.toArray();
		outer: for (ASN1CertChainImportResult asn1CertChainImportResult : certChainImprortResultArray) {
			ASN1CertImportResult[] asn1CertImportResults = asn1CertChainImportResult.toArray();
			for (ASN1CertImportResult asn1CertImportResult : asn1CertImportResults) {
				if(asn1CertImportResult.hasErrors() || asn1CertImportResult.hasNotifications())
					setOutcome(USER_FEEDBACK_OUTCOME);			
				break outer;
			}
		}
		
		if(getOutcome()==null)
			setOutcome(ANNOUNCE_OUTCOME);

	}
}
