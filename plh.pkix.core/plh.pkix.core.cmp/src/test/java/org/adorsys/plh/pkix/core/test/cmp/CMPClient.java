package org.adorsys.plh.pkix.core.test.cmp;

import java.io.File;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.adorsys.plh.pkix.core.cmp.CMPAccount;
import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.smime.plooh.AccountManager;
import org.adorsys.plh.pkix.core.smime.plooh.AccountManagerFactory;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.SimpleActionHandler;
import org.adorsys.plh.pkix.core.utils.plooh.PloohAccount;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;

public class CMPClient {
	
	private final FilesContainer filesContainer;
	private final CMPMessenger cmpMessenger;

	private final Map<String, CMPAccount> cmpAccounts = new HashMap<String, CMPAccount>();
	
	public CMPClient(CMPMessenger cmpMessenger, File workspaceDir, String containerName, char[] containerKeyPass, char[] containerStorePass) {
		
		File containerDir = new File(workspaceDir, containerName);
		
		filesContainer = AccountManagerFactory.loadOrCreateFilesContainer(containerDir, containerKeyPass, containerStorePass);
		this.cmpMessenger = cmpMessenger;
		load();// load registered accounts
	}
	
	private void load() {
		List<AccountManager> accountManagers = AccountManagerFactory.loadAccountManagers(filesContainer);
		for (AccountManager accountManager : accountManagers) {
			ActionContext accountContext = accountManager.getAccountContext();
			accountContext.put(CMPMessenger.class, cmpMessenger);
			accountContext.put(ActionHandler.class, new SimpleActionHandler());
			accountContext.put(AccountManager.class, accountManager);
			FileWrapper accountDir = accountManager.getAccountDir();
			PloohAccount ploohAccount = new PloohAccount(accountDir, accountContext);
			CMPAccount cmpAccount = new CMPAccount(ploohAccount);
			cmpAccounts.put(accountDir.getName(), cmpAccount);
		}
	}
	
	public CMPAccount newAccount(String userName, String email, char[] userSuppliedPassword) {
		String accountDirName = "account_"+BigInteger.probablePrime(7, new Random());
		AccountManager accountManager = AccountManagerFactory.createAccountManager(filesContainer, accountDirName, userName, email, userSuppliedPassword);
		ActionContext accountContext = accountManager.getAccountContext();
		accountContext.put(CMPMessenger.class, cmpMessenger);
		accountContext.put(ActionHandler.class, new SimpleActionHandler());
		accountContext.put(AccountManager.class, accountManager);
		FileWrapper accountDir = accountManager.getAccountDir();
		PloohAccount ploohAccount = new PloohAccount(accountDir, accountContext);
		CMPAccount cmpAccount = new CMPAccount(ploohAccount);
		cmpAccounts.put(accountDir.getName(), cmpAccount);
		return cmpAccount;
	}
}
