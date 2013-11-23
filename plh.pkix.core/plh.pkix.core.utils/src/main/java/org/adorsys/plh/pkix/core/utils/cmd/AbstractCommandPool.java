package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.HashSet;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

public abstract class AbstractCommandPool implements CommandPool {
	
	protected PoolStatus poolStatus = PoolStatus.BLANK;
	
	protected final ActionContext commandContext;

	private final CommandPool nextInchain;
	
	private final Set<CommandPoolListner> listners = new HashSet<CommandPoolListner>();

	public AbstractCommandPool(ActionContext commandContext, CommandPool nextInChain) {
		this.commandContext = commandContext;
		this.nextInchain = nextInChain;
	}

	@Override
	public CommandPool getNextInchain() {
		return nextInchain;
	}

	@Override
	public void shutdown() {
		poolStatus = PoolStatus.TERMINATING;
		getNextInchain().shutdown();
		poolStatus = PoolStatus.DOWN;
	}
	
	protected void checkRunning(){
		if(poolStatus.ordinal()<PoolStatus.RUNNING.ordinal())throw new IllegalStateException("Pool not yet running.");		
		if(poolStatus.ordinal()>PoolStatus.RUNNING.ordinal())throw new IllegalStateException("Pool not longer running.");
	}

	protected void checkDown(){
		if(poolStatus.ordinal()>PoolStatus.RUNNING.ordinal())throw new IllegalStateException("Pool not longer running.");
	}
	
	@Override
	public void afterExecution(Command command) {
		String methodName =Thread.currentThread().getStackTrace()[1].getMethodName();		
		enteringOperation(this, methodName, command);
		getNextInchain().afterExecution(command);
		leavingOperation(this, methodName, null, command);
	}

	@Override
	public void addCommandPoolListner(CommandPoolListner listener) {
		listners.add(listener);
	}

	@Override
	public void removeCommandPoolListner(CommandPoolListner listener) {
		listners.remove(listener);
	}	
	
	protected void enteringOperation(CommandPool source, String operation, Object... params){
		for (CommandPoolListner commandPoolListner : listners) {
			commandPoolListner.enteringOperation(source, operation, params);
		}
	}
	
	protected void leavingOperation(CommandPool source, String operation, Object result, Object... params){
		for (CommandPoolListner commandPoolListner : listners) {
			commandPoolListner.leavingOperation(source, operation, params, result);
		}
	}
}
