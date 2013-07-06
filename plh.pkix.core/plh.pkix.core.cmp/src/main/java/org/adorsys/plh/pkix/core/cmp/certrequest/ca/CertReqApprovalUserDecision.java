package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertTemplateProcessingResult;

/**
 * This class executes the decision of the user on how to proceed with a certification request.
 * 
 * @author fpo
 *
 */
public class CertReqApprovalUserDecision extends GenericAction {
	/**
	 * Certify and send back certificate to the user.
	 */
	public static final String CERTIFY_OUTCOME="certify";
	
	/**
	 * Reject certification request, using reasons (errors and notifications) available 
	 * in the {@link ASN1CertTemplateProcessingResult} object.
	 */
	public static final String REJECT_OUTCOME="reject";
	
	/**
	 * Pause the request for late processing, without sending any notification to the user.
	 * The request will be paused and can manually resumed by the user. The request will not be 
	 * automatically resumed.
	 */
	public static final String PAUSE_OUTCOME="pause";

	/**
	 * Send a poll response to the user, with the time amount this user needs to process the 
	 * request. Requester will have to wait for that amount of time before polling. 
	 */
	public static final String CHECK_LATER_OUTCOME="check_later";

	private final BuilderChecker checker = new BuilderChecker(CertReqApprovalUserDecision.class);
	public CertReqApprovalUserDecision(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		
		addProcessor(CERTIFY_OUTCOME, CertReqCertifyActionProcessor.class);
		setOutcome(CERTIFY_OUTCOME);
	}
}
