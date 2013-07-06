package org.adorsys.plh.pkix.core.cmp.stores;

import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

public class IncomingRequests extends CMPRequests {
	
	private static final String REQUEST_DIR_NAME = "request_in";
	public IncomingRequests(FileWrapper accountDir) {
		super(accountDir);
	}
	
	@Override
	public String getRequestDir() {
		return REQUEST_DIR_NAME;
	}
}
