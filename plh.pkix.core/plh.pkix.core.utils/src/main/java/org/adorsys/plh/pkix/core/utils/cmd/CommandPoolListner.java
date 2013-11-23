package org.adorsys.plh.pkix.core.utils.cmd;

/**
 * Listens to operation performed on a command pool.
 * 
 * @author fpo
 *
 */
public interface CommandPoolListner {

	public void enteringOperation(CommandPool source, String operation, Object[] params);
	
	public void leavingOperation(CommandPool source, String operation, Object[] params, Object result);
}
