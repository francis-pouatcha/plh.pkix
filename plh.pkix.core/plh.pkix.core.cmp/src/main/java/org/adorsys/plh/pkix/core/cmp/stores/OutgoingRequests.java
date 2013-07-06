package org.adorsys.plh.pkix.core.cmp.stores;

import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

public class OutgoingRequests extends CMPRequests {
	
	private static final String REQUEST_DIR_NAME = "request_out";
	public OutgoingRequests(FileWrapper accountDir) {
		super(accountDir);
	}
	
	@Override
	public String getRequestDir() {
		return REQUEST_DIR_NAME;
	}
}
