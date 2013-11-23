package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.concurrent.ScheduledFuture;

public class ScheduledCommand implements Runnable {

	private final Command command;
	
	private final CommandPool commandPool;
	
	ScheduledFuture<?> future;
	
	public ScheduledCommand(Command command, CommandPool commandPool) {
		super();
		this.command = command;
		this.commandPool = commandPool;
	}

	@Override
	public void run() {
		commandPool.getNextInchain().addCommand(command);
	}

	public ScheduledFuture<?> getFuture() {
		return future;
	}

	public void setFuture(ScheduledFuture<?> future) {
		this.future = future;
	}

	public Command getCommand() {
		return command;
	}
	
}
