package org.adorsys.plh.pkix.core.utils.cmd;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

/**
 * Invoke the after execution method of a command in a new thread.
 * 
 * @author fpo
 *
 */
public class ExecutorCompletionTask implements Runnable {

	private final Command command;
	private final ActionContext commandContext;

	@Override
	public void run() {
		command.afterExecution();
		CommandPool commandPool = commandContext.get(CommandPool.class);
		if(commandPool!=null){
			commandPool.afterExecution(command);
		}
	}

	public ExecutorCompletionTask(Command command, ActionContext commandContext) {
		super();
		this.command = command;
		this.commandContext = commandContext;
	}

}
