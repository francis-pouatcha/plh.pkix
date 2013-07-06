package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivator;
import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivators;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.bouncycastle.asn1.cmp.PKIBody;

public class CertificationResponseActivator extends ModuleActivator{

	private CertReqValidationProcessor incomingProcessor = new CertReqValidationProcessor();
	
	public CertificationResponseActivator(ActionContext accountContext,
			FileWrapper accountDir, ModuleActivators moduleActivators) {
		super(accountContext, accountDir, moduleActivators);
	}

	@Override
	protected void activate(ActionContext actionContext, FileWrapper accountDir) {
		actionContext.put(CertReqApprovalActionProcessor.class, new CertReqApprovalActionProcessor());
		actionContext.put(CertReqCertifyActionProcessor.class, new CertReqCertifyActionProcessor());
		actionContext.put(CertReqResponseActionProcessor.class, new CertReqResponseActionProcessor());
		actionContext.put(CertReqResponseSendActionProcessor.class, new CertReqResponseSendActionProcessor());
		actionContext.put(CertReqApprovalUserFeedbackProcessor.class, new CertReqApprovalUserFeedbackProcessor());
	}

	@Override
	public ActionProcessor getIncommingProcessor() {
		return incomingProcessor;
	}

	@Override
	public Integer getIncomingMessageType() {
		return PKIBody.TYPE_CERT_REQ;
	}
}
