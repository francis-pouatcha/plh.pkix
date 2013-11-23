package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

/**
 * Check every 2 seconds.
 * 
 * @author fpo
 *
 */
public class MailServerAvailableConditionMonitor implements ConditionMonitor, Runnable {
	private static final String CONTION_IDENTIFIER = MailServerAvailableCondition.class.getName();
	private final ActionContext commandContext;
	private final List<ConditionListener> conditionListeners = new ArrayList<ConditionListener>();
	
	public MailServerAvailableConditionMonitor(ActionContext commandContext, ScheduledExecutorService executor) {
		this.commandContext = commandContext;
		this.commandContext.put(MailServerAvailableConditionMonitor.class, this);
		executor.scheduleWithFixedDelay(this, 1, 3, TimeUnit.SECONDS);
	}

	@Override
	public void addConditionListener(ConditionListener conditionListener) {
		conditionListeners.add(conditionListener);
	}

	@Override
	public void removeConditionListener(ConditionListener conditionListener) {
		conditionListeners.remove(conditionListener);
	}

	private boolean isAvailable(){
		MailServerSimulator mailServerSimulator = commandContext.get(MailServerSimulator.class);
		return mailServerSimulator.isAvailable();		
	}

	@Override
	public void run() {
		if(isAvailable()){
			for (ConditionListener conditionListener : conditionListeners) {
				conditionListener.favorable(CONTION_IDENTIFIER);
			}
		} else {
			for (ConditionListener conditionListener : conditionListeners) {
				conditionListener.unfavorable(CONTION_IDENTIFIER);
			}
		}
	}
}
