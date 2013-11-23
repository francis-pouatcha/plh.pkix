package org.adorsys.plh.pkix.core.utils.cmd;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

public class SimpleCommandEngine {
	
	private final CommandPool commandPool;
	private final ActionContext commandContext;
	
	public SimpleCommandEngine(CommandStore commandStore, ActionContext commandContext){
		
		this.commandContext = commandContext;
		
		// NullCommandPool
		NullCommandPool nullCommandPool = new NullCommandPool();
		
		// PriorityCommandPool
		PriorityCommandPool priorityCommandPool = new PriorityCommandPool(commandContext, nullCommandPool);
		// ConditionalCommandPool
		ConditionalCommandPool conditionalCommandPool = new ConditionalCommandPool(commandContext, priorityCommandPool);
		// ScheduledCommandPool
		SchedulingCommandPool schedulingCommandPool = new SchedulingCommandPool(commandContext, conditionalCommandPool);
		// PersistentCommandPool
		PersistentCommandPool persistentCommandPool = new PersistentCommandPool(commandContext, schedulingCommandPool, commandStore);
		
		// set root
		this.commandPool = persistentCommandPool;
		// register with context.
		commandContext.put(CommandPool.class, commandPool);
	}

	public CommandPool getCommandPool() {
		return commandPool;
	}
	
	public void initialize(){
		commandPool.initialize();
	}
	
	public void shutdown(){
		commandPool.shutdown();
	}

	public ActionContext getCommandContext() {
		return commandContext;
	}
}
