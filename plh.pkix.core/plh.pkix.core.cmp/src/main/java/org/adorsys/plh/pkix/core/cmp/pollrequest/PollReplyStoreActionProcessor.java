package org.adorsys.plh.pkix.core.cmp.pollrequest;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;

public class PollReplyStoreActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(PollReplyStoreActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {
//
//		PKIMessageActionData actionData = actionContext.get(PKIMessageActionData.class);
//		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class,null);
//		PendingRequests pendingRequests = actionContext.get(PendingRequests.class);
//		
//		checker.checkNull(actionData,keyStoreWraper,pendingRequests);
//		
//		PKIMessage pkiMessage = actionData.getPkiMessage();
//		PKIBody pkiBody = pkiMessage.getBody();
//		PollRepContent pollRepContent = PollRepContent.getInstance(pkiBody.getContent());
//
//		ASN1Integer checkAfter = pollRepContent.getCheckAfter();
//		Date nextPollSeconds = DateUtils.addSeconds(new Date(), checkAfter.getValue().intValue());
//		DERGeneralizedTime nextPoll = new DERGeneralizedTime(nextPollSeconds);
//		
//		ASN1Integer certReqId = pollRepContent.getCertReqId();
//		BigInteger certReqIdBigInteger = pollRepContent.getCertReqId().getPositiveValue();
//		PendingRequestData pendingRequestData = pendingRequests.loadPendingRequest(certReqIdBigInteger);
//		if(pendingRequestData==null){
//			PendingRequest pendingRequest = new PendingRequest(certReqId, pkiMessage, nextPoll, pkiMessage, null, null);
//			pendingRequestData = new PendingRequestData(pendingRequest);
//		} else {
//			PendingRequest pendingRequest = pendingRequestData.getPendingRequest();
//			pendingRequest = new PendingRequest(
//					pendingRequest.getCertReqId(), 
//					pendingRequest.getPkiMessage(), 
//					nextPoll, pkiMessage, 
//					pendingRequest.getPollReqMessage(), 
//					pendingRequest.getDisposed());
//			pendingRequestData = new PendingRequestData(pendingRequest);
//		}
//		pendingRequests.storePollRequestHolder(certReqIdBigInteger, pendingRequestData);
	}
}
