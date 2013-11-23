package org.adorsys.plh.pkix.core.utils.cmd;

/**
 * Each command condition has a condition monitor. This monitor can host references
 * to listeners and notify them when the condition applies
 * 
 * @author fpo
 *
 */
public interface ConditionMonitor {

	public void addConditionListener(ConditionListener conditionListener);
	
	public void removeConditionListener(ConditionListener conditionListener);
}
