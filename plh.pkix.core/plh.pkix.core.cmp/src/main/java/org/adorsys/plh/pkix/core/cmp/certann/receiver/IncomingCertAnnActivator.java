package org.adorsys.plh.pkix.core.cmp.certann.receiver;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivator;
import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivators;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.bouncycastle.asn1.cmp.PKIBody;

public class IncomingCertAnnActivator extends ModuleActivator {

	IncomingCertAnnValidationProcessor incomingProcessor = new IncomingCertAnnValidationProcessor();
	public IncomingCertAnnActivator(ActionContext accountContext,
			FileWrapper accountDir, ModuleActivators moduleActivators) {
		super(accountContext, accountDir, moduleActivators);
	}

	@Override
	protected void activate(ActionContext actionContext, FileWrapper accountDir) {
		actionContext.put(IncomingCertAnnImportActionProcessor.class, new IncomingCertAnnImportActionProcessor());		
	}

	@Override
	public ActionProcessor getIncommingProcessor() {
		return incomingProcessor;		
	}

	@Override
	public Integer getIncomingMessageType() {
		return PKIBody.TYPE_CERT_ANN;
	}
}
