package org.adorsys.plh.pkix.core.utils.cmd;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.text.ParseException;
import java.util.concurrent.TimeUnit;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

/**
 * Default implementation of a command.
 * 
 * @author fpo
 *
 */
public abstract class AbstractCommand implements Command {
	protected final String handle;
	protected final ActionContext commandContext;
	protected ExecutionPlan executionPlan;
	protected CommandCondition condition;

	protected AbstractCommand(ActionContext commandContext) {
		this.commandContext = commandContext;

		CommandActionData commandActionData = commandContext.get(CommandActionData.class);
		if(commandActionData==null)throw new IllegalStateException("MIssing command data context.");

		ASN1Command asn1Command = commandActionData.getAsn1Command();
		
		this.handle = asn1Command.getCommandHandle().getString();
		
		ASN1ExecutionPlan asn1ExecutionPlan = asn1Command.getExecutionPlan();
		if(asn1ExecutionPlan!=null){
			try {
				this.executionPlan = new ExecutionPlan(asn1ExecutionPlan.getExecutionTime().getDate(), asn1ExecutionPlan.getFixRate().getValue().longValue(), TimeUnit.valueOf(asn1ExecutionPlan.getTimeUnit().getString()));
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		}

		DERIA5String conditionId = asn1Command.getConditionId();
		if(conditionId!=null){
			try {
				@SuppressWarnings("unchecked")
				Class<? extends CommandCondition> conditionClass = (Class<? extends CommandCondition>) AbstractCommand.class.getClassLoader().loadClass(conditionId.getString());
				this.condition = commandContext.get(conditionClass);
			} catch (ClassNotFoundException e) {
				throw new IllegalStateException(e);
			}
			if(this.condition==null)
				throw new IllegalStateException("Missing condition associated with condition class: "+ conditionId.getString() + "; Parent context must preinitialize all command conditions.");
		}
	}
	
	protected AbstractCommand(String handle, ActionContext parentContext, ExecutionPlan executionPlan, CommandCondition condition) {
		this.commandContext = new ActionContext(parentContext);
		this.handle = handle;
		this.executionPlan = executionPlan;
		this.condition = condition;
	}

	@Override
	public int compareTo(Command o) {
		return handle.compareTo(o.getHandle());
	}

	@Override
	public String getHandle() {
		return handle;
	}

	@Override
	public ExecutionPlan getExecutionPlan() {
		return executionPlan;
	}

	@Override
	public void afterExecution() {
		// noop
	}

	@Override
	public CommandCondition getCondition() {
		return condition;
	}

	@Override
	public ActionContext getCommandContext() {
		return commandContext;
	}
	
	private ASN1ExecutionPlan getAsn1ExecutionPlan(){
		ExecutionPlan executionPlan = getExecutionPlan();
		if(executionPlan==null) return null;
		
		DERGeneralizedTime executionTime = new DERGeneralizedTime(executionPlan.getExecutionTime());
		ASN1Integer fixRate = new ASN1Integer(executionPlan.getFixRate());
		DERIA5String timeUnit = new DERIA5String(executionPlan.getTimeUnit().name());
		return new ASN1ExecutionPlan(executionTime, fixRate, timeUnit);
	}
	
	private DERIA5String getASN1ConditionId(){
		CommandCondition condition = getCondition();
		if(condition==null)return null;
		return new DERIA5String(condition.getConditionId());
	}
	
	public void store(FileWrapper commandStoreDir){
		
		// Create and add command data to the command context for serialization.
		ASN1Command asn1Command = new ASN1Command(new DERIA5String(getHandle()), new DERIA5String(getClass().getName()), getAsn1ExecutionPlan(), getASN1ConditionId());
		CommandActionData commandActionData = new CommandActionData(asn1Command);
		commandContext.put(CommandActionData.class, commandActionData);
		
		// serialize the command context to a file carrying the handle name.
		FileWrapper commandDir = commandStoreDir.newChild(getHandle());
		FileWrapper commandFile = commandDir.newChild(getHandle());
		OutputStream outputStream = commandFile.newOutputStream();
		commandContext.store(outputStream);
		IOUtils.closeQuietly(outputStream);
	}
	
	@SuppressWarnings("rawtypes")
	private static final Class[] commandConstructorParams = new Class[]{ActionContext.class};
	public static AbstractCommand load(FileWrapper commandFile, ActionContext parent) throws Exception {
		// Load action context from stream
		ActionContext actionContext = new ActionContext(parent);
		InputStream inputStream = commandFile.newInputStream();
		actionContext.load(inputStream);
		CommandActionData commandActionData = actionContext.get(CommandActionData.class);
		if(commandActionData==null)throw new IllegalStateException("Command action data not in context.");
		
		// Instantiate command object
		ASN1Command asn1Command = commandActionData.getAsn1Command();
		DERIA5String commandClassName = asn1Command.getCommandClassName();
		String string = commandClassName.getString();
		@SuppressWarnings("unchecked")
		Class<? extends AbstractCommand> commandClass = (Class<? extends AbstractCommand>) AbstractCommand.class.getClassLoader().loadClass(string);
		Constructor<? extends AbstractCommand> constructor = commandClass.getConstructor(commandConstructorParams);
		
		
		return constructor.newInstance(actionContext);
	}
}
