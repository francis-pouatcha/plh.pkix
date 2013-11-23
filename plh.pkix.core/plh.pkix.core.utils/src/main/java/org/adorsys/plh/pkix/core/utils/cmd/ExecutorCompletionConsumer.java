package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

/**
 * This task synchronously take completed task from the associated execution completion service
 * and forward processing to another task.
 * 
 * @author fpo
 *
 */
public class ExecutorCompletionConsumer implements Runnable {

	private final ExecutorCompletionService<Command> ecs;
	private final ExecutorService executor;
	private final ActionContext commandContext;

	public ExecutorCompletionConsumer(ExecutorCompletionService<Command> ecs,
			ExecutorService executor, ActionContext commandContext) {
		super();
		this.ecs = ecs;
		this.executor = executor;
		this.commandContext = commandContext;
	}

	@Override
	public void run() {
		Command command = null;
		try {
			Future<Command> take = ecs.take();
			command = take.get();
		} catch (InterruptedException e) {
			// no op
		} catch (ExecutionException e) {
			// no op
		}
		if(command!=null){
			ExecutorCompletionTask task = new ExecutorCompletionTask(command, commandContext);
			executor.execute(task);
		}
	}
}
