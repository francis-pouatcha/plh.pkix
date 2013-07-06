package org.adorsys.plh.pkix.core.utils.action;

import java.util.List;

import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;

public class SimpleActionHandler implements ActionHandler {
	
	@Override
	public void handle(List<Action> actions) {
		for (Action action : actions) {
			String outcome = action.getOutcome();
			if(outcome==null)
				throw PlhUncheckedException.toException(new NullPointerException("outcome is null"), SimpleActionHandler.class);
			Class<? extends ActionProcessor> actionProcessorClass = action.getActionProcessor(outcome);
			if(actionProcessorClass==null)
				throw PlhUncheckedException.toException(new NullPointerException("actionProcessorClass is null"), SimpleActionHandler.class);

			ActionContext actionContext = action.getActionContext();
			ActionProcessor actionProcessor = actionContext.get(actionProcessorClass);
			if(actionProcessor==null){
				throw PlhUncheckedException.toException(new NullPointerException(), SimpleActionHandler.class);
			} else {
				actionProcessor.process(actionContext);
			}
		}
	}
}
