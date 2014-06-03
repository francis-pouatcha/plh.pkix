package org.adorsys.plh.pkix.client.ui;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collection;
import java.util.Locale;
import java.util.Properties;

import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import javax.enterprise.inject.Instance;

import org.adorsys.plh.pkix.core.client.MainController;
import org.adorsys.plh.pkix.core.client.locale.LocaleFactory;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.jboss.weld.environment.se.Weld;

/**
 * This is the plooh main client application. It is in charge of the plooh installation and the management
 * of plooh instances on a computer.
 * 
 * <h1>Installation Directory</h1>
 * 
 * <h3>Location of the installation directory</h3>
 * The plooh installation directory never matter. It is the location where the plooh bynaries are
 * located and configured the the administrator of the computer. 
 * 
 * <h3>Protecting the installation directory</h3>
 * If possible, this installation directory shall be readable but not be writable by a standard user.
 * 
 * If it is easier to protect a user directory, the application can be configure to store a password
 * enriched signature of the application itself in the user directory.
 * 
 * If the user directory has the same exposition like the application directory, using an external device
 * to store those bootstrap information might be better.
 * 
 * The better way to protect the application will strongly depend on the environment in which the application
 * is installed and run.
 * 
 * <h1>User Directory: ${user.dir}/.plooh</h1>
 * 
 * The plooh user directory is the location used to manage a <b>plooh user instance</b>.
 * 
 * <h3>Locating the user directory</h3>
 * The plooh user directory is the ${user.dir} returned by the jvm. In order to test plooh in 
 * the maven /target directory, this property can be overridden by setting the property 
 * ${plooh.user.dir} system property prior to loading the test class. In the case of junit in the 
 * @BeforeClass annotated method.
 * 
 * <h3>Protecting the user directory</h3>
 * 
 * The user directory can be protected using a secret question whose answer is used to encrypt the 
 * user directory's bootstraping information.
 * 
 * @TODO Key classes in the application will have to be designed to enforce this policy.
 * 
 * <h1>User instance<h1>
 * A plooh runtime application running on a user directory is called a plooh user instance. A plooh
 * user instance can run many plooh workspaces in parallel. Each plooh workspace running on a proper
 * jvm.
 * 
 * <h1>Workspace</h1>
 * 
 * Each plooh runtime instance works on exactly one workspace. When a user starts a plooh application,
 * the application uses properties stored in the plooh user directory to discover workspaces managed by 
 * the starting user instance.
 * 
 * <h3>Locating the workspace</h3>
 * <ul>
 * 	<li>If only one workspace is defined, the application automatically starts that workspace.</li>
 * 	<li>If more than one workspaces are started, the application prompts the user to select a workspace.</li>
 * 	<li>If no workspace is started, the application checks the existance of the system property ${plooh.workspace.default}</li>
 * 		<ul>
 * 			<li>If the default workspace is defined, the application automatically starts using the default workspace. In case the 
 * 				default workspace is in used by another plooh user instance, the application prompts the user
 * 				to select a new workspace.</li>
 * 			<li>If the default workspace is not defined, the application uses the value ${plooh.user.dir}/plooh as the default workspace.</li>
 * 		</ul>
 *	</li>
 * </ul>
 * 
 * <h3>Protecting the workspace<h3>
 * Each Workspace can be optionally protected by a secret question's answer.
 * A plooh workspace instance can only be executed from the original plooh user instance. 
 * This is because the key used to access information stored in the workspace is retrieved from the user bootstrap directory.
 * 
 * If a plooh instance has many workspaces, the application will prompt the user to select one of them.
 * 
 * <h3>Mutual Exclusion</h3>
 * Only one workspace instance can be active on a workspace directory at a time. Plooh provides a
 * workspace thread that continuously update the status of the workspace instance. This happens every 
 * minute. So if a plooh instance crashes, restarting on the same workspace will be possible after one minute.
 * 
 * @author fpo
 *
 */
public class PloohClient extends Application {
	private Weld weld;
	private static Locale locale;

	public static void main(String[] args) {
		// parse locale
		for (int i = 0; i < args.length; i++) {
			String arg = args[i];
			if (StringUtils.isBlank(arg))
				continue;

			if (StringUtils.equalsIgnoreCase(arg, "-L")
					|| StringUtils.equalsIgnoreCase(arg, "--locale")) {
				if (args.length > i + 1) {
					try {
						locale = new Locale(args[i + 1]);
						Locale.setDefault(locale);
					} catch (Exception ex) {
						throw new IllegalStateException(ex);
					}
				}
			}
		}
		
		if(locale==null){
			File file = new File("appconfig.properties");
			if(file.exists()){
				Properties properties = new Properties();
				try {
					properties.load(new FileInputStream(file));
					String localeProperty = properties.getProperty("locale");
					if(locale==null){
						locale = new Locale(localeProperty);
						Locale.setDefault(locale);
					}
				} catch (FileNotFoundException e) {
					throw new IllegalStateException(e);
				} catch (IOException e) {
					throw new IllegalStateException(e);
				}
			}
		}

		if (locale == null) {
			locale = Locale.getDefault();
		}
		if (locale == null) {
			locale = new Locale("fr");
			Locale.setDefault(locale);
		}

		launch(args);
	}

	@Override
	public void init() {
		weld = new Weld();
	}

	@Override
	public void start(Stage stage) {
		stage.setOnCloseRequest(new EventHandler<WindowEvent>() {
			public void handle(WindowEvent event) {
				Collection<File> listFiles = FileUtils.listFiles(new File("."), new String[]{"pdf"}, false);
				for (File file : listFiles) {
					if(file.getName().endsWith("pdf"))FileUtils.deleteQuietly(file);
				}
			}
		});
		Instance<Object> instance = weld.initialize().instance();
		instance.select(LocaleFactory.class).get().setLocale(locale);
		instance.select(MainController.class).get()
				.start(stage, locale, "styles/application.css");
	}

	@Override
	public void stop() {
		weld.shutdown();
	}	
	/**
	 * The main directory on which this application is operating.
	 */
//	private final FilesContainer filesContainer;
	
//	public PloohClient(File workspaceDir, String containerName, char[] containerKeyPass, char[] containerStorePass) {
//		
//		File containerDir = new File(workspaceDir, containerName);
//		
//		filesContainer = AccountManagerFactory.loadOrCreateFilesContainer(containerDir, containerKeyPass, containerStorePass);
//		load();// load registered accounts
//	}
//	
//	private void load() {
//		List<AccountManager> accountManagers = AccountManagerFactory.loadAccountManagers(filesContainer);
//		for (AccountManager accountManager : accountManagers) {
//			ActionContext accountContext = accountManager.getAccountContext();
//			accountContext.put(CMPMessenger.class, cmpMessenger);
//			accountContext.put(ActionHandler.class, new SimpleActionHandler());
//			accountContext.put(AccountManager.class, accountManager);
//			FileWrapper accountDir = accountManager.getAccountDir();
//			PloohAccount ploohAccount = new PloohAccount(accountDir, accountContext);
//			CMPAccount cmpAccount = new CMPAccount(ploohAccount);
//			cmpAccounts.put(accountDir.getName(), cmpAccount);
//		}
//	}
//	
//	public CMPAccount newAccount(String userName, String email, char[] userSuppliedPassword) {
//		String accountDirName = "account_"+BigInteger.probablePrime(7, new Random());
//		AccountManager accountManager = AccountManagerFactory.createAccountManager(filesContainer, accountDirName, userName, email, userSuppliedPassword);
//		ActionContext accountContext = accountManager.getAccountContext();
//		accountContext.put(CMPMessenger.class, cmpMessenger);
//		accountContext.put(ActionHandler.class, new SimpleActionHandler());
//		accountContext.put(AccountManager.class, accountManager);
//		FileWrapper accountDir = accountManager.getAccountDir();
//		PloohAccount ploohAccount = new PloohAccount(accountDir, accountContext);
//		CMPAccount cmpAccount = new CMPAccount(ploohAccount);
//		cmpAccounts.put(accountDir.getName(), cmpAccount);
//		return cmpAccount;
//	}
}
