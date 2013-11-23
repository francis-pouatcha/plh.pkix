package org.adorsys.plh.pkix.core.utils.cmd;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SimpleCommandEngineTest {

	
	private CommandStore commandStore;
	private SimpleCommandEngine simpleCommandEngine;

	@Before
	public void before(){
		ActionContext commandContext = new ActionContext();
		commandStore = new CommandStore() {
			private final Map<String, Command> commands = new HashMap<String, Command>();
			@Override
			public void storeCommand(Command command) {
				commands.put(command.getHandle(), command);
			}
			
			@Override
			public void removeCommand(String handle) {
				commands.remove(handle);
			}
			
			@Override
			public Command loadCommand(String handle) {
				return commands.get(handle);
			}
			
			@Override
			public List<String> handles() {
				return new ArrayList<String>(commands.keySet());
			}
		};		
		simpleCommandEngine = new SimpleCommandEngine(commandStore, commandContext);
		simpleCommandEngine.initialize();

		new MailServerSimulator(commandContext);
		ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);
		new MailServerAvailableCondition(commandContext);
		new MailServerAvailableConditionMonitor(commandContext, executor);
	}

	@Test
	public void testNullCommand() {
		CommandPool commandPool = simpleCommandEngine.getCommandPool();
		Command command = new NullCommand(UUID.randomUUID().toString());
		commandPool.addCommand(command );
		simpleCommandEngine.shutdown();
	}
	
	@Test
	public void testSendMail(){
		
		// Moovie Script.
		ActionContext commandContext = simpleCommandEngine.getCommandContext();
		CommandPool commandPool = simpleCommandEngine.getCommandPool();
		MailSendCmd mailSendCmd = new MailSendCmd(UUID.randomUUID().toString(), commandContext, "This is an object set");
		MailServerSimulator mailServerSimulator = commandContext.get(MailServerSimulator.class);
		mailServerSimulator.setAvailable(true);
		ArrayBlockingQueue<Command> addBlockingQueue = new ArrayBlockingQueue<Command> (10);
		
		TestCommandPoolListener priorityAddListener = new TestCommandPoolListener(addBlockingQueue,"addCommand");
		PriorityCommandPool priorityCommandPool = commandContext.get(PriorityCommandPool.class);
		priorityCommandPool.addCommandPoolListner(priorityAddListener);
		
		ArrayBlockingQueue<Command> afterExecBlockingQueue = new ArrayBlockingQueue<Command> (10);
		TestCommandPoolListener priorityAfterExecListener = new TestCommandPoolListener(afterExecBlockingQueue,"afterExecution");
		priorityCommandPool.addCommandPoolListner(priorityAfterExecListener);

		
		// Moovie
		commandPool.addCommand(mailSendCmd);
		
		try {
			// wait 5 seconds for the next command.
			Command command = addBlockingQueue.poll(5, TimeUnit.SECONDS);
			Assert.assertEquals(mailSendCmd, command);
		} catch (InterruptedException e1) {
			throw new IllegalStateException(e1);
		}
		try {
			// wait 5 seconds for the next command.
			Command command = afterExecBlockingQueue.poll(5, TimeUnit.SECONDS);
			Assert.assertEquals(mailSendCmd, command);
			Assert.assertTrue(mailSendCmd.isCalled());
		} catch (InterruptedException e1) {
			throw new IllegalStateException(e1);
		}
	}

	@Test
	public void testSendMailNoServer(){
		
		// Moovie Script.
		ActionContext commandContext = simpleCommandEngine.getCommandContext();
		CommandPool commandPool = simpleCommandEngine.getCommandPool();
		MailSendCmd mailSendCmd = new MailSendCmd(UUID.randomUUID().toString(), commandContext, "This is an object set");
		ArrayBlockingQueue<Command> addBlockingQueue = new ArrayBlockingQueue<Command> (10);
		
		TestCommandPoolListener priorityAddListener = new TestCommandPoolListener(addBlockingQueue,"addCommand");
		PriorityCommandPool priorityCommandPool = commandContext.get(PriorityCommandPool.class);
		priorityCommandPool.addCommandPoolListner(priorityAddListener);
		
		ArrayBlockingQueue<Command> afterExecBlockingQueue = new ArrayBlockingQueue<Command> (10);
		TestCommandPoolListener priorityAfterExecListener = new TestCommandPoolListener(afterExecBlockingQueue,"afterExecution");
		priorityCommandPool.addCommandPoolListner(priorityAfterExecListener);

		
		// Moovie
		commandPool.addCommand(mailSendCmd);
		
		try {
			// wait 5 seconds for the next command.
			Command command = addBlockingQueue.poll(5, TimeUnit.SECONDS);
			Assert.assertNotEquals(mailSendCmd, command);
			Assert.assertFalse(mailSendCmd.isCalled());
		} catch (InterruptedException e1) {
			throw new IllegalStateException(e1);
		}
	}
	
	@Test
	public void testSendMailReactivatedServer(){
		
		// Moovie Script.
		ActionContext commandContext = simpleCommandEngine.getCommandContext();
		CommandPool commandPool = simpleCommandEngine.getCommandPool();
		MailSendCmd mailSendCmd = new MailSendCmd(UUID.randomUUID().toString(), commandContext, "This is an object set");

		ArrayBlockingQueue<Command> addBlockingQueue = new ArrayBlockingQueue<Command> (10);
		
		TestCommandPoolListener priorityAddListener = new TestCommandPoolListener(addBlockingQueue,"addCommand");
		PriorityCommandPool priorityCommandPool = commandContext.get(PriorityCommandPool.class);
		priorityCommandPool.addCommandPoolListner(priorityAddListener);
		
		ArrayBlockingQueue<Command> afterExecBlockingQueue = new ArrayBlockingQueue<Command> (10);
		TestCommandPoolListener priorityAfterExecListener = new TestCommandPoolListener(afterExecBlockingQueue,"afterExecution");
		priorityCommandPool.addCommandPoolListner(priorityAfterExecListener);
		
		// Moovie
		commandPool.addCommand(mailSendCmd);
		
		try {
			// wait 5 seconds for the next command.
			Command command = addBlockingQueue.poll(5, TimeUnit.SECONDS);
			Assert.assertNotEquals(mailSendCmd, command);
			Assert.assertFalse(mailSendCmd.isCalled());
		} catch (InterruptedException e1) {
			throw new IllegalStateException(e1);
		}
		
		MailServerSimulator mailServerSimulator = commandContext.get(MailServerSimulator.class);
		mailServerSimulator.setAvailable(true);
		
		try {
			// wait 5 seconds for the next command.
			Command command = addBlockingQueue.poll(5, TimeUnit.SECONDS);
			Assert.assertEquals(mailSendCmd, command);
		} catch (InterruptedException e1) {
			throw new IllegalStateException(e1);
		}
		try {
			// wait 5 seconds for the next command.
			Command command = afterExecBlockingQueue.poll(5, TimeUnit.SECONDS);
			Assert.assertEquals(mailSendCmd, command);
			Assert.assertTrue(mailSendCmd.isCalled());
		} catch (InterruptedException e1) {
			throw new IllegalStateException(e1);
		}
	}
	
	
	static class TestCommandPoolListener implements CommandPoolListner{
		protected String methodName;
		protected ArrayBlockingQueue<Command> arrayBlockingQueue;		
		public TestCommandPoolListener(ArrayBlockingQueue<Command> arrayBlockingQueue, String methodName) {
			this.arrayBlockingQueue = arrayBlockingQueue;
			this.methodName = methodName;
			try {
				Method method = CommandPool.class.getMethod(methodName, Command.class);
				methodName = method.getName();
			} catch (Exception e) {
				throw new IllegalStateException(e);
			}
		}

		@Override
		public void enteringOperation(CommandPool source, String operation,
				Object[] params) {
			if(!methodName.equals(operation)) return;
			for (int i = 0; i < params.length; i++) {
				if(params[i] instanceof Command)
					try {
						arrayBlockingQueue.put((Command) params[i]);
					} catch (InterruptedException e) {
						throw new IllegalStateException(e);
					}
			}
		}

		@Override
		public void leavingOperation(CommandPool source, String operation,
				Object[] params, Object result) {
		}
	}
}
