package org.adorsys.plh.pkix.core.cmp.certann.sender;

import java.util.Date;
import java.util.concurrent.Executor;

import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.cmp.message.ExecutorConstants;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.i18n.ErrorBundle;

public class OutgoingCertAnnSendActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(OutgoingCertAnnSendActionProcessor.class);
	
	// @Asynch
	@Override
	public void process(ActionContext actionContext) {
		final CMPMessenger cmpMessenger = actionContext.get(CMPMessenger.class);
		final OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		checker.checkNull(cmpMessenger, requests);
		
		final CMPRequest request = actionContext.get(CMPRequest.class);
		checker.checkNull(request);
		
		Executor executor = actionContext.get1(Executor.class, ExecutorConstants.OUTGOING_REQUEST_EXECUTOR_NAME);
		checker.checkNull(executor);
		
		executor.execute(new Runnable() {	
			@Override
			public void run() {
				PKIMessage requestMessage = requests.loadRequest(request);
				DERGeneralizedTime now = new DERGeneralizedTime(new Date());
				requests.lock(request);
				try {					
					cmpMessenger.send(requestMessage);
					request.setDisposed(now);
					requests.setResultAndNextAction(request, null, new DERIA5String(ProcessingStatus.SUCCESS), null, null);
				} catch(PlhUncheckedException e){
					ErrorMessageHelper.processError(request, requests, e.getErrorMessage());
				} catch (RuntimeException r){
					ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(r, getClass().getName()+"#process");
					ErrorMessageHelper.processError(request, requests, errorMessage);
				} finally {
					requests.unlock(request);
				} 
			}
		});
	}
}
