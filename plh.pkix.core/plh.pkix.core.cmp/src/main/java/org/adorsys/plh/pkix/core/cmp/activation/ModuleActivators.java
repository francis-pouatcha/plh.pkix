package org.adorsys.plh.pkix.core.cmp.activation;

import java.util.HashMap;
import java.util.Map;

import org.adorsys.plh.pkix.core.cmp.certann.receiver.IncomingCertAnnActivator;
import org.adorsys.plh.pkix.core.cmp.certann.sender.OutgoingCertAnnActivator;
import org.adorsys.plh.pkix.core.cmp.certrequest.ca.CertificationResponseActivator;
import org.adorsys.plh.pkix.core.cmp.certrequest.endentity.CertificationRequestActivator;
import org.adorsys.plh.pkix.core.cmp.initrequest.receiver.IncomingInitializationRequestActivator;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.OutgoingInitializationRequestActivator;
import org.adorsys.plh.pkix.core.cmp.registration.RegistrationRequestActivator;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

public class ModuleActivators {

	private Map<Integer, ModuleActivator> modules = new HashMap<Integer, ModuleActivator>();

	public ModuleActivators(ActionContext accountContext, FileWrapper accountDir) {
		new CertificationRequestActivator(accountContext, accountDir, this);
		new CertificationResponseActivator(accountContext, accountDir, this);
		new IncomingCertAnnActivator(accountContext, accountDir, this);
		new OutgoingCertAnnActivator(accountContext, accountDir, this);
		new IncomingInitializationRequestActivator(accountContext, accountDir, this);
		new OutgoingInitializationRequestActivator(accountContext, accountDir, this);
		new RegistrationRequestActivator(accountContext, accountDir, this);
	}
	
	public ModuleActivator getModuleActivator(Integer messageType){
		return modules.get(messageType);
	}

	public void addActivator(ModuleActivator moduleActivator) {
		modules.put(moduleActivator.getIncomingMessageType(), moduleActivator);
	}
}
