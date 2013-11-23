package org.adorsys.plh.pkix.core.utils.cmd;

/**
 * Holds a set of commands that are to be executed. Also schedules execution of those commands
 * depending on the responsibility of this pool in the chain of CommandPools.
 * 
 * @author fpo
 *
 */
public interface CommandPool {

	/**
	 * Add a command to the pool. Depending on the responsibility of this pool, this
	 * method can either schedule execution, persistence or odering of the command.
	 * 
	 * @param command
	 * @return
	 */
	public void addCommand(Command command);
	
	/**
	 * Remove a command from the pool. This is not equivalent to canceling the command.
	 * 
	 * @param command
	 * @return
	 */
	public Command removeCommand(Command command);
	
	/**
	 * Remove a command from the pool. This is not equivalent to canceling the command.
	 * 
	 * @param handle
	 * @return
	 */
	public Command removeCommand(String handle);
	
	/**
	 * Retrieves the command with the given handle.
	 * 
	 * @param handle
	 * @return
	 */
	public Command getCommand(String handle);
	
	/**
	 * Cancel the given command. Whether the command will be removed from the list of 
	 * commands 
	 * 
	 * @param command
	 */
	public void cancelCommand(Command command);

	/**
	 * Cancel the given command.
	 * 
	 * @param handle
	 */
	public void cancelCommand(String handle);
	
	/**
	 * Cancel all commands.
	 */
	public void cancelAll();
	
	/**
	 * Initialize this command pool.
	 */
	public void initialize();
	
	/**
	 * Shuts down this command pool.
	 */
	public void shutdown();
	
	/**
	 * Implements the chain of responsibility.
	 * 
	 * @return
	 */
	public CommandPool getNextInchain();

	/**
	 * Called when command execution is terminated
	 * 
	 * @param command
	 */
	public void afterExecution(Command command);	
	
	public void addCommandPoolListner(CommandPoolListner listener);
	
	public void removeCommandPoolListner(CommandPoolListner listener);
}
