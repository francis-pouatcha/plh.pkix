package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.concurrent.Future;

public class ExecutingCommand {
	
	private final Command command;
	
	private final Future<Command> future;

	public ExecutingCommand(Command command, Future<Command> future) {
		super();
		this.command = command;
		this.future = future;
	}

	public Command getCommand() {
		return command;
	}

	public Future<Command> getFuture() {
		return future;
	}
}
