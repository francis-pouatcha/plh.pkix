package org.adorsys.plh.pkix.core.utils.cmd;

/**
 * This is the condition that will have to be fulfilled prior to the execution
 * of the carrying command.
 *  
 * @author fpo
 *
 */
public interface CommandCondition {

	/**
	 * Return true if the condition applies at the moment where this method is called.
	 * 
	 * @return
	 */
	public boolean favorable();
	
	/**
	 * Returns the identifier of this condition.
	 * @return
	 */
	public String getConditionId();
	
	/**
	 * Returns the monitor in charge of this condition.
	 * 
	 * @return
	 */
	public ConditionMonitor getConditionMonitor();
}
