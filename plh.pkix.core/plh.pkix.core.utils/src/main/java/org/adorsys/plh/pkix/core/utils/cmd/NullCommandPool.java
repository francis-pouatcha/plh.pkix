package org.adorsys.plh.pkix.core.utils.cmd;

public class NullCommandPool implements CommandPool {

	@Override
	public void addCommand(Command command) {
		// noop
	}

	@Override
	public Command removeCommand(Command command) {
		return null;
	}

	@Override
	public Command removeCommand(String handle) {
		return null;
	}

	@Override
	public Command getCommand(String handle) {
		return null;
	}

	@Override
	public void cancelCommand(Command command) {
		// npop
	}

	@Override
	public void cancelCommand(String handle) {
		// npop
	}

	@Override
	public void cancelAll() {
		// npop
	}

	@Override
	public void initialize() {
		// npop
	}

	@Override
	public void shutdown() {
		// npop
	}

	@Override
	public CommandPool getNextInchain() {
		return null;
	}

	@Override
	public void afterExecution(Command command) {
		// npop
	}

	@Override
	public void addCommandPoolListner(CommandPoolListner listener) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeCommandPoolListner(CommandPoolListner listener) {
		// TODO Auto-generated method stub
		
	}
}
