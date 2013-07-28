package org.adorsys.plh.pkix.core.cmp;

import java.security.KeyStore.PrivateKeyEntry;
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
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.SimpleActionHandler;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

/**
 * This is a wraper arround the plooh account for cmp functionality.
 * @author fpo
 *
 */
public class CMPAccount {

	private final UserAccount userAccount;

	public CMPAccount(UserAccount userAccount, CMPMessenger cmpMessenger) {
		this.userAccount = userAccount;
		ActionContext accountContext = userAccount.getAccountContext();
		accountContext.put(ActionHandler.class, new SimpleActionHandler());
		accountContext.put(CMPMessenger.class, cmpMessenger);

		FileWrapper accountDir = userAccount.getAccountDir();
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

	public UserAccount getUserAccount() {
		return userAccount;
	}

	/**
	 * Register's this account with the messaging server.
	 */
	public void registerAccount(){
		List<PrivateKeyEntry> privateKeyEntries = userAccount.findAllMessagePrivateKeyEntries();
		PrivateKeyEntry messagePrivateKeyEntry = privateKeyEntries.iterator().next();

		ActionContext actionContext = new ActionContext(userAccount.getAccountContext());
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
		ActionContext actionContext = new ActionContext(userAccount.getAccountContext());
		actionContext.put(InitializationRequestFieldHolder.class, f);
		OutgoingInitializationRequestInitActionProcessor actionProcessor = actionContext.get(OutgoingInitializationRequestInitActionProcessor.class);
		actionProcessor.process(actionContext);
	}
	
	public void sendCertificationRequest(CertificationRequestFieldHolder f){
		ActionContext actionContext = new ActionContext(userAccount.getAccountContext());
		actionContext.put(CertificationRequestFieldHolder.class, f);
		CertificationRequestInitActionProcessor actionProcessor = actionContext.get(CertificationRequestInitActionProcessor.class);
		actionProcessor.process(actionContext);
	}
}
