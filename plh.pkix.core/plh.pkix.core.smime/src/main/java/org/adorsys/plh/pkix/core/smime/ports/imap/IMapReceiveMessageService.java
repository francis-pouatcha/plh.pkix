package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class IMapReceiveMessageService {

	private final IMapReceiveMessageWorker receiveMessageWorker;
	
	private final IMapDeleteRecievedMessageWorker deleteRecievedMessageWorker;

	public IMapReceiveMessageService(EmailAccountConfig emailAccountConfig) {
		ScheduledExecutorService service = emailAccountConfig.getExecutionService();

		receiveMessageWorker = new IMapReceiveMessageWorker(emailAccountConfig);
		service.scheduleAtFixedRate(receiveMessageWorker, 1, 5, TimeUnit.SECONDS);

		deleteRecievedMessageWorker = new IMapDeleteRecievedMessageWorker(emailAccountConfig);
		service.scheduleAtFixedRate(deleteRecievedMessageWorker, 1, 60, TimeUnit.SECONDS);
	}
	
}
