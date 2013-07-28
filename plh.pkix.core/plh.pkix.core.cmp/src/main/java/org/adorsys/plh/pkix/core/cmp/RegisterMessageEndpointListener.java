package org.adorsys.plh.pkix.core.cmp;

/**
 * GEt notified when a new message end point is registered.
 * 
 * @author fpo
 *
 */
public interface RegisterMessageEndpointListener {

	public void newMessageEndpoint(String publicKeyIdHex);
}
