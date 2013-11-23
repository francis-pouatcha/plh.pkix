package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.List;

/**
 * Provide a functionality to store and retrieve command objects.
 * 
 * @author fpo
 *
 */
public interface CommandStore {

	public void storeCommand(Command command);
	
	public Command loadCommand(String handle);
	
	public void removeCommand(String handle);
	
	public List<String> handles();
}
