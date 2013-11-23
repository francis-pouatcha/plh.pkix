package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

public class SchedulingCommandPool extends AbstractCommandPool {

	private ScheduledThreadPoolExecutor executor;
	
	private Map<String, ScheduledCommand> scheduledCommandMap = new HashMap<String, ScheduledCommand>();
	
	// TODO: externalize property
	private int corePoolSize = 2;

	public SchedulingCommandPool(ActionContext commandContext, CommandPool nextInChain) {
		super(commandContext,nextInChain);
		executor = new ScheduledThreadPoolExecutor(corePoolSize);
	}

	@Override
	public void addCommand(Command command) {
		checkDown();
		
		long nowMs = System.currentTimeMillis();
		ExecutionPlan executionPlan = command.getExecutionPlan();
		if(executionPlan!=null){
			Date execMs = executionPlan.getExecutionTime();
			ScheduledCommand scheduledCommand = new ScheduledCommand(command, this);
			long delay = execMs.getTime()-nowMs;
			long fixRate = executionPlan.getFixRate();
			TimeUnit timeUnit = executionPlan.getTimeUnit();
			if(fixRate>0){
				if(delay<0) delay=0;
				scheduledCommandMap.put(command.getHandle(), scheduledCommand);
				ScheduledFuture<?> scheduleAtFixedRate = executor.scheduleAtFixedRate(scheduledCommand, delay, fixRate, timeUnit);
				scheduledCommand.setFuture(scheduleAtFixedRate);
			} else if (delay>0){
				scheduledCommandMap.put(command.getHandle(), scheduledCommand);
				ScheduledFuture<?> scheduledFuture = executor.schedule(scheduledCommand, delay, timeUnit);
				scheduledCommand.setFuture(scheduledFuture);
			} else {
				getNextInchain().addCommand(command);
			}
		} else {
			getNextInchain().addCommand(command);
		}
	}

	@Override
	public Command removeCommand(Command command) {
		checkRunning();
		
		String handle = command.getHandle();
		ScheduledCommand scheduledCommand = scheduledCommandMap.get(handle);
		if(scheduledCommand!=null){
			ScheduledFuture<?> future = scheduledCommand.getFuture();
			future.cancel(false);
			scheduledCommandMap.remove(handle);
		}
		// remove it in the chain down.
		getNextInchain().removeCommand(command);
		return command;
	}

	@Override
	public Command removeCommand(String handle) {
		checkRunning();

		ScheduledCommand scheduledCommand = scheduledCommandMap.get(handle);
		Command removedCommand = null;
		if(scheduledCommand!=null){
			ScheduledFuture<?> future = scheduledCommand.getFuture();
			future.cancel(false);
			scheduledCommandMap.remove(handle);
			removedCommand = scheduledCommand.getCommand();
		}
		// remove it in the chain down.
		removedCommand = getNextInchain().removeCommand(handle);
		return removedCommand;
	}

	@Override
	public Command getCommand(String handle) {
		checkRunning();

		ScheduledCommand scheduledCommand = scheduledCommandMap.get(handle);
		if(scheduledCommand!=null)
			return scheduledCommand.getCommand();
		
		return getNextInchain().getCommand(handle);
	}

	@Override
	public void cancelCommand(Command command) {
		checkRunning();
		
		String handle = command.getHandle();
		ScheduledCommand scheduledCommand = scheduledCommandMap.get(handle);
		if(scheduledCommand!=null){
			ScheduledFuture<?> future = scheduledCommand.getFuture();
			future.cancel(false);
		}
		getNextInchain().cancelCommand(command);
	}

	@Override
	public void cancelCommand(String handle) {
		checkRunning();

		ScheduledCommand scheduledCommand = scheduledCommandMap.get(handle);
		if(scheduledCommand!=null){
			ScheduledFuture<?> future = scheduledCommand.getFuture();
			future.cancel(false);
		}
		getNextInchain().cancelCommand(handle);
	}

	@Override
	public void cancelAll() {
		checkRunning();

		Collection<ScheduledCommand> values = scheduledCommandMap.values();
		for (ScheduledCommand scheduledCommand : values) {
			ScheduledFuture<?> future = scheduledCommand.getFuture();
			future.cancel(false);
		}
		getNextInchain().cancelAll();
	}

	@Override
	public void initialize() {
		if(poolStatus.ordinal()>PoolStatus.BLANK.ordinal())throw new IllegalStateException("Pool initializing or already initialized.");		
		
		poolStatus = PoolStatus.INITIALIZING;
		getNextInchain().initialize();
		
		poolStatus = PoolStatus.RUNNING;
	}
}
