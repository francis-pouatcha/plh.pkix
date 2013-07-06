package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivator;
import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivators;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.bouncycastle.asn1.cmp.PKIBody;

public class OutgoingInitializationRequestActivator extends ModuleActivator {

	InitializationResponseValidationActionProcessor incomingProcessor = new InitializationResponseValidationActionProcessor();
	public OutgoingInitializationRequestActivator(ActionContext accountContext,
			FileWrapper accountDir, ModuleActivators moduleActivators) {
		super(accountContext, accountDir, moduleActivators);
	}

	@Override
	protected void activate(ActionContext actionContext, FileWrapper accountDir) {
		actionContext.put(OutgoingInitializationRequestInitActionProcessor.class, new OutgoingInitializationRequestInitActionProcessor());
		actionContext.put(OutgoingInitializationRequestSendActionProcessor.class, new OutgoingInitializationRequestSendActionProcessor());		

		actionContext.put(InitializationResponseAcceptActionPreProcessor.class, new InitializationResponseAcceptActionPreProcessor());		
		actionContext.put(InitializationResponseImportActionProcessor.class, new InitializationResponseImportActionProcessor());	
		actionContext.put(InitializationResponseAcceptUserFeedbackProcessor.class, new InitializationResponseAcceptUserFeedbackProcessor());	
		actionContext.put(InitializationResponseValidationUserFeedbackProcessor.class, new InitializationResponseValidationUserFeedbackProcessor());	
	}

	@Override
	public ActionProcessor getIncommingProcessor() {
		return incomingProcessor;		
	}

	@Override
	public Integer getIncomingMessageType() {
		return PKIBody.TYPE_INIT_REP;
	}
}
