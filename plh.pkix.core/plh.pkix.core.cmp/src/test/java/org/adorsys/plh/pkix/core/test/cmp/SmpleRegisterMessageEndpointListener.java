package org.adorsys.plh.pkix.core.test.cmp;

import java.util.concurrent.BlockingQueue;

import org.adorsys.plh.pkix.core.cmp.RegisterMessageEndpointListener;

public class SmpleRegisterMessageEndpointListener implements
		RegisterMessageEndpointListener {
	BlockingQueue<String> endPointQueue;
	
	
	public SmpleRegisterMessageEndpointListener(
			BlockingQueue<String> endPointQueue) {
		super();
		this.endPointQueue = endPointQueue;
	}


	@Override
	public void newMessageEndpoint(String email) {
		endPointQueue.offer(email);
	}

}
