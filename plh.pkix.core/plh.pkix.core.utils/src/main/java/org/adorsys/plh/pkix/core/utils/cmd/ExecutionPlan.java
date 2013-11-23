package org.adorsys.plh.pkix.core.utils.cmd;

import java.util.Date;
import java.util.concurrent.TimeUnit;

public class ExecutionPlan {

	private final Date executionTime;

	private final long fixRate;

	private final TimeUnit timeUnit;

	public ExecutionPlan(Date executionTime, long fixRate, TimeUnit timeUnit) {
		super();
		this.executionTime = executionTime;
		this.fixRate = fixRate;
		this.timeUnit = timeUnit;
	}

	public Date getExecutionTime() {
		return executionTime;
	}

	public long getFixRate() {
		return fixRate;
	}

	public TimeUnit getTimeUnit() {
		return timeUnit;
	}
}
