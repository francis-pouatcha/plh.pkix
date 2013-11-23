package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.concurrent.FutureTask;

public class CommandTask extends FutureTask<Command> implements
		Comparable<CommandTask> {

	private Command command;
	
	public CommandTask(Command command) {
		super(command);
	}

	@Override
	public int compareTo(CommandTask o) {
		return command.compareTo(o.command);
	}

}
