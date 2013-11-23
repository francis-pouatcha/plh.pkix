package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.concurrent.Callable;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

/**
 * This is an interface for operation we want execute in this controlled environment.
 * 
 * The {@link Comparable} interface is implemented to allow the implementation of
 * priorities.
 * 
 * The {@link Callable} interface allow the retrieval of result and exception in asynchronous calls.
 * 
 * In order to make a command persistent, user can implement the {@link PersistentCommand} interface and
 * provide an corresponding {@link CommandStore} implementation to take care of the persistence of those 
 * commands.
 * 
 * @author fpo
 *
 */
public interface Command extends Comparable<Command>, Callable<Command> {

	/**
	 * Returns a command identifier. Whether or not this identifier should be
	 * unique on the semantic of the command pool that uses it.
	 * 
	 * A {@link CommandPool} that executes the same command many times might have another 
	 * way of maintaining references to executed commands.
	 * 
	 * @return
	 */
	public String getHandle();
	
	/**
	 * Returns the execution plan of this command.
	 * 
	 * @return
	 */
	public ExecutionPlan getExecutionPlan();
	
	/**
	 * This method is call after the task is executed to enable for task chaining.
	 */
	public void afterExecution();
	
	/**
	 * Returns the condition for this command or null if this command has no condition.
	 * @return
	 */
	public CommandCondition getCondition();
	
	/**
	 * Returns the action context of this command object.
	 * 
	 * @return
	 */
	public ActionContext getCommandContext();
	
	/**
	 * Write this command to the file system.
	 * @param commandStoreDir
	 */
	public void store(FileWrapper commandStoreDir);
}
