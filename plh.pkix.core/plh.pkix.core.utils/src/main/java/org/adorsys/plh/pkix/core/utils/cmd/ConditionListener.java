package org.adorsys.plh.pkix.core.utils.cmd;

/**
 * This listener gets notified when a condition fires.
 * 
 * @author fpo
 *
 */
public interface ConditionListener {

	public void favorable(String conditionIdentifier);

	public void unfavorable(String conditionIdentifier);
}
