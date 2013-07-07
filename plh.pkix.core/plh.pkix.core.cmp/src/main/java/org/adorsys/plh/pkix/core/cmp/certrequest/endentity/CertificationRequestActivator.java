package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivator;
import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivators;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.bouncycastle.asn1.cmp.PKIBody;

public class CertificationRequestActivator extends ModuleActivator {

	CertificationReplyValidationProcessor incomingProcessor = new CertificationReplyValidationProcessor();
	public CertificationRequestActivator(ActionContext accountContext,
			FileWrapper accountDir, ModuleActivators moduleActivators) {
		super(accountContext, accountDir, moduleActivators);
	}

	@Override
	protected void activate(ActionContext actionContext, FileWrapper accountDir) {
		actionContext.put(CertificationRequestInitActionProcessor.class, new CertificationRequestInitActionProcessor());
		actionContext.put(CertificationRequestSendActionProcessor.class, new CertificationRequestSendActionProcessor());		

		actionContext.put(CertificationReplyAcceptActionPreProcessor.class, new CertificationReplyAcceptActionPreProcessor());		
		actionContext.put(CertificationReplyImportActionProcessor.class, new CertificationReplyImportActionProcessor());
		
		actionContext.put(CertificationReplyAcceptUserFeedbackProcessor.class, new CertificationReplyAcceptUserFeedbackProcessor());
		actionContext.put(CertificationReplyValidationUserFeedbackProcessor.class, new CertificationReplyValidationUserFeedbackProcessor());
		actionContext.put(CertificationReplyImportUserFeedbackProcessor.class, new CertificationReplyImportUserFeedbackProcessor());
	}

	@Override
	public ActionProcessor getIncommingProcessor() {
		return incomingProcessor;		
	}

	@Override
	public Integer getIncomingMessageType() {
		return PKIBody.TYPE_CERT_REP;
	}
}
