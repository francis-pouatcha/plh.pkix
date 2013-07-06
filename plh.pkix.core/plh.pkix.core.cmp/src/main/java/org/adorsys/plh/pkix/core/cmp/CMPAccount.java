package org.adorsys.plh.pkix.core.cmp;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivators;
import org.adorsys.plh.pkix.core.cmp.certrequest.endentity.CertificationRequestFieldHolder;
import org.adorsys.plh.pkix.core.cmp.certrequest.endentity.CertificationRequestInitActionProcessor;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.InitializationRequestFieldHolder;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.OutgoingInitializationRequestInitActionProcessor;
import org.adorsys.plh.pkix.core.cmp.message.ExecutorConstants;
import org.adorsys.plh.pkix.core.cmp.registration.RegistrationRequestInitActionProcessor;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.contact.ContactListener;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.bouncycastle.cert.X509CertificateHolder;

public class CMPAccount {

	private ActionContext accountContext;

	public CMPAccount(FileWrapper accountDir, ActionContext accountContext) {
		this.accountContext = accountContext;

		ModuleActivators moduleActivators = new ModuleActivators(accountContext, accountDir);
		
		ExecutorService executors_out = Executors.newFixedThreadPool(5);
		accountContext.put(Executor.class, ExecutorConstants.OUTGOING_REQUEST_EXECUTOR_NAME, executors_out);
		ExecutorService executors_in = Executors.newFixedThreadPool(5);
		accountContext.put(Executor.class, ExecutorConstants.INCOMMING_REQUEST_EXECUTOR_NAME, executors_in);		

		CMPMessageEndpoint cmpMessageEndpoint = new AsynchCMPMessageEndpoint(executors_in, new DispatchingCMPMessageEndpoint(moduleActivators, accountContext));
		accountContext.put(CMPMessageEndpoint.class, cmpMessageEndpoint);
		accountContext.put(OutgoingRequests.class, new OutgoingRequests(accountDir));
		accountContext.put(IncomingRequests.class, new IncomingRequests(accountDir));
		
	}
	
	/**
	 * Register's this account with the messaging server.
	 */
	public void registerAccount(){
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		PrivateKeyEntry messagePrivateKeyEntry = contactManager.getMainMessagePrivateKeyEntry();

		actionContext.put(PrivateKeyEntry.class, messagePrivateKeyEntry);
		RegistrationRequestInitActionProcessor processor = actionContext.get(RegistrationRequestInitActionProcessor.class);	
		processor.process(actionContext);
	}

	/**
	 * Sends an initialization request to another user, using the user's email.
	 * 
	 * @param email
	 */
	public void sendInitializationRequest(InitializationRequestFieldHolder f) {
		ActionContext actionContext = new ActionContext(accountContext);
		actionContext.put(InitializationRequestFieldHolder.class, f);
		OutgoingInitializationRequestInitActionProcessor actionProcessor = actionContext.get(OutgoingInitializationRequestInitActionProcessor.class);
		actionProcessor.process(actionContext);
	}
	
	public List<TrustedCertificateEntry> findContacts(String email){
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		return contactManager.findMessageEntriesByEmail(TrustedCertificateEntry.class, email);
	}
	
	public void sendCertificationRequest(CertificationRequestFieldHolder f){
		ActionContext actionContext = new ActionContext(accountContext);
		actionContext.put(CertificationRequestFieldHolder.class, f);
		CertificationRequestInitActionProcessor actionProcessor = actionContext.get(CertificationRequestInitActionProcessor.class);
		actionProcessor.process(actionContext);
	}
	
	public PrivateKeyEntry getMainMessagePrivateKey(){
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		return contactManager.getMainMessagePrivateKeyEntry();
	}
	public PrivateKeyEntry findMessagePrivateKeyByIssuer(X509CertificateHolder issuerCertificate) {
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		return contactManager.findMessageEntryByIssuerCertificate(PrivateKeyEntry.class, issuerCertificate);
	}
	
	public TrustedCertificateEntry findCaSigningCertificateByEmail(String caEmail){
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		return contactManager.findCaEntryByEmail(TrustedCertificateEntry.class, caEmail);
	}

	public TrustedCertificateEntry findMessagingCertificateByEmail(String caEmail){
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		return contactManager.findMessageEntryByEmail(TrustedCertificateEntry.class, caEmail);
	}

	public void addContactListener(ContactListener contactListener){
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		contactManager.addContactListener(contactListener);
	}
}
