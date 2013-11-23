package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.File;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.cmd.CommandPool;
import org.adorsys.plh.pkix.core.utils.cmd.CommandPoolListner;
import org.adorsys.plh.pkix.core.utils.cmd.CommandStore;
import org.adorsys.plh.pkix.core.utils.cmd.MailServerAvailableCondition;
import org.adorsys.plh.pkix.core.utils.cmd.MailServerAvailableConditionMonitor;
import org.adorsys.plh.pkix.core.utils.cmd.MailServerSimulator;
import org.adorsys.plh.pkix.core.utils.cmd.SimpleCommandEngine;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.UnprotectedFileWraper;
import org.junit.Before;
import org.junit.Test;

public class PersistentComandTest {

	private SimpleCommandEngine simpleCommandEngine;

	@Before
	public void before(){
		
		ActionContext commandContext = new ActionContext();
		FileWrapper commandStoreDir = new UnprotectedFileWraper("commandStore", new File("target/PersistentComandTest"));
		CommandStore commandStore = new FileCommandStore(commandStoreDir, commandContext);

		simpleCommandEngine = new SimpleCommandEngine(commandStore, commandContext);
		simpleCommandEngine.initialize();

		new MailServerSimulator(commandContext);
		ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);
		new MailServerAvailableCondition(commandContext);
		new MailServerAvailableConditionMonitor(commandContext, executor);
	}

	@Test
	public void test() {
		ActionContext commandContext = simpleCommandEngine.getCommandContext();
	    final CountDownLatch barrier = new CountDownLatch(1);
		final SmplPersistentCommand cmd = new SmplPersistentCommand(UUID.randomUUID().toString(), commandContext);
		
		CommandPoolListner poolListner = new CommandPoolListner() {
			
			@Override
			public void leavingOperation(CommandPool source, String operation,
					Object[] params, Object result) {
				if(cmd.equals(result)){
					barrier.countDown();
				}
			}
			
			@Override
			public void enteringOperation(CommandPool source, String operation,
					Object[] params) {
				// NOOP
			}
		};
		simpleCommandEngine.getCommandPool().addCommandPoolListner(poolListner);
		simpleCommandEngine.getCommandPool().addCommand(cmd);
		
		try {
			barrier.await(5, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			// NOOP
		}
	}

}
