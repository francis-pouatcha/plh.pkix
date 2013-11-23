package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.List;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

/**
 * Maintains a persistent list of commands to be executed.
 * 
 * @author fpo
 *
 */
public class PersistentCommandPool extends AbstractCommandPool {

	private CommandStore commandStore;
	
	public PersistentCommandPool(ActionContext commandContext, CommandPool nextInChain, CommandStore commandStore) {
		super(commandContext,nextInChain);
		this.commandStore = commandStore;
	}

	@Override
	public void addCommand(Command command) {
		checkRunning();
		commandStore.storeCommand(command);
		getNextInchain().addCommand(command);
	}
	
	@Override
	public Command removeCommand(Command command) {
		checkRunning();
		
		commandStore.removeCommand(command.getHandle());

		Command cmd = getNextInchain().removeCommand(command);
		return cmd;
	}

	@Override
	public Command removeCommand(String handle) {
		checkRunning();
		
		commandStore.removeCommand(handle);
		
		return getNextInchain().removeCommand(handle);
	}

	@Override
	public Command getCommand(String handle) {
		checkRunning();

		Command cmd = commandStore.loadCommand(handle);
		if(cmd!=null) return cmd;
		return getNextInchain().getCommand(handle);// might not be a persistent command.
	}

	@Override
	public void cancelCommand(Command command) {
		checkRunning();
		// we do not cancel persistent version of a command. It can be removed.
		getNextInchain().cancelCommand(command);
	}

	@Override
	public void cancelCommand(String handle) {
		checkRunning();
		// we do not cancel persistent version of a command. It can be removed.
		getNextInchain().cancelCommand(handle);
	}

	@Override
	public void cancelAll() {
		checkRunning();
		getNextInchain().cancelAll();
	}

	@Override
	public void initialize() {
		if(poolStatus.ordinal()>PoolStatus.BLANK.ordinal())throw new IllegalStateException("Pool initializing or already initialized.");		
		
		poolStatus = PoolStatus.INITIALIZING;
		List<String> handles = commandStore.handles();
		getNextInchain().initialize();
		poolStatus = PoolStatus.RUNNING;
		for (String handle : handles) {
			Command command = commandStore.loadCommand(handle);
			getNextInchain().addCommand(command);
		}
	}
}
