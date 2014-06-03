package org.adorsys.plh.pkix.core.smime.plooh;

import java.net.InetAddress;
import java.net.UnknownHostException;

public abstract class ContainerNameUtils {

	public static String getContainerName(String userName){
		InetAddress localMachine;
		try {
			localMachine = InetAddress.getLocalHost();
		} catch (UnknownHostException e) {
			throw new IllegalStateException(e);
		}
		return userName+"@"+localMachine;
		
	}
}
