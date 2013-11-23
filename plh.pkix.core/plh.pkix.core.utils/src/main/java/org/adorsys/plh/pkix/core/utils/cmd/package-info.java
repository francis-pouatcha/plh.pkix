/**
 * 
 */
/**
 * Implements a command execution engines with following specific behavior.
 * <ol>
 * <li>Command submitted for execution are persistent. This means a command register will first store this command
 * into a local, reliable persistent storage before making it available for further execution.</li>
 * <li>Command Execution can be tight to a schedule. In which case this command will only be submitted for further execution when due.</li>
 * <li>Command execution can be tied to conditions. Availability of a network service: If the network service (e.g a mail server) is not available, the execution of all 
 * 			due command depending on the service will still be delayed.</li>
 * <li>Decoupling execution completion: post processing of the command is passed to another thread that uses a registered completion handler to process the result.</li>
 * <li>In order to be able to cancel execution of a submitted command, a command future pool is maintained keyed by the command id.</li>
 * </ol>
 * @author fpo
 *
 */
package org.adorsys.plh.pkix.core.utils.cmd;