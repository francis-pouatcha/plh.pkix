package org.adorsys.plh.pkix.core.cmp.certann.sender;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivator;
import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivators;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

public class OutgoingCertAnnActivator extends ModuleActivator {

	public OutgoingCertAnnActivator(ActionContext accountContext,
			FileWrapper accountDir, ModuleActivators moduleActivators) {
		super(accountContext, accountDir, moduleActivators);
	}

	@Override
	protected void activate(ActionContext actionContext, FileWrapper accountDir) {
		actionContext.put(OutgoingCertAnnActionProcessor.class, new OutgoingCertAnnActionProcessor());
		actionContext.put(OutgoingCertAnnSendActionProcessor.class, new OutgoingCertAnnSendActionProcessor());		
	}

	@Override
	public ActionProcessor getIncommingProcessor() {
		return null;		
	}

	@Override
	public Integer getIncomingMessageType() {
		return null;
	}
}
