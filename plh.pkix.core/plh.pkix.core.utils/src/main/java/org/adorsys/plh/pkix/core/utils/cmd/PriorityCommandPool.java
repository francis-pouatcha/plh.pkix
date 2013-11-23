package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

public class PriorityCommandPool extends AbstractCommandPool {

	private final ThreadPoolExecutor executor;
	private final ExecutorCompletionService<Command> ecs;
	private final List<Command> preInitList = new ArrayList<Command>();
	private final Map<String, Set<ExecutingCommand>> commandMap = new HashMap<String, Set<ExecutingCommand>>();
	private final BlockingQueue<Runnable> commandQueue = new PriorityBlockingQueue<Runnable>();
	private final ExecutorService completionExecutor;

	private PoolStatus poolStatus = PoolStatus.BLANK;
	
	public PriorityCommandPool(ActionContext commandContext, CommandPool nextInChain) {
		super(commandContext, nextInChain);
		int corePoolSize = 5;
		int maximumPoolSize = 2000000;
		long keepAliveTime = 10;
		TimeUnit unit = TimeUnit.SECONDS;
		executor = new ThreadPoolExecutor(corePoolSize, maximumPoolSize, keepAliveTime, unit , commandQueue);
		ecs = new ExecutorCompletionService<Command>(executor);
		completionExecutor = Executors.newCachedThreadPool();
		commandContext.put(PriorityCommandPool.class, this);
	}

	@Override
	public void addCommand(Command command) {
		String methodName =Thread.currentThread().getStackTrace()[1].getMethodName();		
		enteringOperation(this, methodName, command);
		checkDown();
		
		if(poolStatus.ordinal()<PoolStatus.RUNNING.ordinal()){
			preInitList.add(command);
		} else {
			addCommandInternal(command);
		}
		leavingOperation(this, methodName, null, command);
	}
	
	private void addCommandInternal(Command command){
		Future<Command> future = ecs.submit(command);
		ExecutingCommand executingCommand = new ExecutingCommand(command, future);
		Set<ExecutingCommand> set = commandMap.get(command.getHandle());
		if(set==null){
			set = new HashSet<ExecutingCommand>();
			commandMap.put(command.getHandle(), set);
		}
		commandMap.get(command.getHandle()).add(executingCommand);
	}

	@Override
	public Command removeCommand(Command command) {
		checkRunning();
		Set<ExecutingCommand> set = commandMap.get(command.getHandle());
		if(set==null) return null;
		commandMap.remove(set);
		for (ExecutingCommand executingCommand : set) {
			executingCommand.getFuture().cancel(false);
			commandQueue.remove(executingCommand.getCommand());
		}
		return command;
	}

	@Override
	public Command removeCommand(String handle) {
		checkRunning();
		Command result = null;
		Set<ExecutingCommand> set = commandMap.get(handle);
		if(set==null) return null;
		commandMap.remove(set);
		for (ExecutingCommand executingCommand : set) {
			executingCommand.getFuture().cancel(false);
			commandQueue.remove(executingCommand.getCommand());
			result = executingCommand.getCommand();
		}
		return result;
	}

	@Override
	public Command getCommand(String handle) {
		checkRunning();
		Set<ExecutingCommand> set = commandMap.get(handle);
		if(set==null) return null;
		for (ExecutingCommand executingCommand : set) {
			return executingCommand.getCommand();
		}
		return null;
	}

	@Override
	public void cancelCommand(Command command) {
		checkRunning();
		Set<ExecutingCommand> set = commandMap.get(command.getHandle());
		if(set==null) return;
		commandMap.remove(set);
		for (ExecutingCommand executingCommand : set) {
			executingCommand.getFuture().cancel(false);
		}
	}

	@Override
	public void cancelCommand(String handle) {
		Set<ExecutingCommand> set = commandMap.get(handle);
		if(set==null) return;
		commandMap.remove(set);
		for (ExecutingCommand executingCommand : set) {
			executingCommand.getFuture().cancel(false);
		}
	}

	@Override
	public void cancelAll() {
		Collection<Set<ExecutingCommand>> values = commandMap.values();
		commandMap.clear();
		for (Set<ExecutingCommand> set : values) {
			for (ExecutingCommand executingCommand : set) {
				executingCommand.getFuture().cancel(false);
			}
		}		
	}

	@Override
	public void initialize() {
		if(poolStatus.ordinal()>PoolStatus.BLANK.ordinal())throw new IllegalStateException("Pool initializing or already initialized.");		
		
		poolStatus = PoolStatus.INITIALIZING;
		for (Command command : preInitList) {
			addCommandInternal(command);
		}
		preInitList.clear();
		
		for (int i = 0; i < 2; i++) {// two threads to read from completion service.
			ExecutorCompletionConsumer executorCompletionConsumer = new ExecutorCompletionConsumer(ecs, completionExecutor, commandContext);
			completionExecutor.execute(executorCompletionConsumer);
		}
		poolStatus = PoolStatus.RUNNING;
	}

	@Override
	public void shutdown() {
		poolStatus = PoolStatus.TERMINATING;
		executor.shutdown();
		poolStatus = PoolStatus.DOWN;
	}
}
