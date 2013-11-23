package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

/**
 * Release a command for execution when conditions are met. As long as conditions are not met, commands are held 
 * here.
 * 
 * @author fpo
 *
 */
public class ConditionalCommandPool extends AbstractCommandPool implements ConditionListener {

	private Map<String, ConditionMonitor> conditionMonitors = new HashMap<String, ConditionMonitor>();
	private Map<String,Map<String,Command>> pendingCommands = new HashMap<String, Map<String,Command>>();
	
	
	public ConditionalCommandPool(ActionContext commandContext, CommandPool nextInChain) {
		super(commandContext,nextInChain);
		commandContext.put(ConditionalCommandPool.class, this);
	}

	@Override
	public void addCommand(Command command) {
		String methodName =Thread.currentThread().getStackTrace()[1].getMethodName();		
		enteringOperation(this, methodName, command);
		CommandCondition condition = command.getCondition();
		if(condition==null || condition.favorable()){
			getNextInchain().addCommand(command);
		} else {
			String conditionId = condition.getConditionId();
			if(!conditionMonitors.containsKey(conditionId)){
				ConditionMonitor conditionMonitor = condition.getConditionMonitor();
				conditionMonitor.addConditionListener(this);
				conditionMonitors.put(conditionId, conditionMonitor);
			}// else already registered
			Map<String,Command> map = pendingCommands.get(conditionId);
			if(map==null){
				map = new HashMap<String,Command>();
				pendingCommands.put(conditionId, map);
			}
			map.put(command.getHandle(), command);
		}
		
		leavingOperation(this, methodName, null, command);
	}

	@Override
	public Command removeCommand(Command command) {
		CommandCondition condition = command.getCondition();
		if(condition==null || !pendingCommands.containsKey(condition.getConditionId())){
			return getNextInchain().removeCommand(command);
		}
		Map<String,Command> map = pendingCommands.get(condition.getConditionId());
		Command found = map.remove(command.getHandle());
		Command removeCommand = getNextInchain().removeCommand(command);
		if(removeCommand!=null) return removeCommand;
		return found;
	}

	@Override
	public Command removeCommand(String handle) {
		Command command = null;
		Map<String,Command> foundMap = null;
		Collection<Map<String,Command>> values = pendingCommands.values();
		for (Map<String, Command> map : values) {
			if(map.containsKey(handle)){
				command = map.get(handle);
				foundMap = map;
				break;
			}
		}
		if(command==null){
			return getNextInchain().removeCommand(command);
		}
		Command found = foundMap.remove(handle);
		Command removeCommand = getNextInchain().removeCommand(command);
		if(removeCommand!=null) return removeCommand;
		return found;
	}

	@Override
	public Command getCommand(String handle) {
		Collection<Map<String,Command>> values = pendingCommands.values();
		for (Map<String, Command> map : values) {
			if(map.containsKey(handle)){
				return map.get(handle);
			}
		}
		return getNextInchain().getCommand(handle);
	}

	@Override
	public void cancelCommand(Command command) {
		removeCommand(command);
	}

	@Override
	public void cancelCommand(String handle) {
		removeCommand(handle);
	}

	@Override
	public void cancelAll() {
		HashSet<Command> commands = new HashSet<Command>();
		Collection<Map<String,Command>> values = pendingCommands.values();
		for (Map<String, Command> map : values) {
			commands.addAll(map.values());
		}
		for (Command command : commands) {
			cancelCommand(command);
		}
	}

	@Override
	public void initialize() {
		if(poolStatus.ordinal()>PoolStatus.BLANK.ordinal())throw new IllegalStateException("Pool initializing or already initialized.");		
		
		poolStatus = PoolStatus.INITIALIZING;
		getNextInchain().initialize();
		
		poolStatus = PoolStatus.RUNNING;
	}

	@Override
	public void favorable(String conditionIdentifier) {
		Map<String, Command> map = pendingCommands.remove(conditionIdentifier);
		if(map==null) return;
		
		Collection<Command> values = map.values();
		for (Command command : values) {
			getNextInchain().addCommand(command);			
		}		
		map.clear();
	}
	
	@Override
	public void unfavorable(String conditionIdentifier) {
		// TODO DUplicate functionality. Start routing command to buffer.
		
	}
	
}
