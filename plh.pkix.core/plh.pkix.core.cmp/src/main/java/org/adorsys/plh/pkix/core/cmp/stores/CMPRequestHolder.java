package org.adorsys.plh.pkix.core.cmp.stores;

import java.util.concurrent.locks.ReentrantLock;

public class CMPRequestHolder  extends ReentrantLock {
	
	private static final long serialVersionUID = -6509330442265935074L;

	private String requestDir;
	
	private CMPRequest cmpRequest;
	
	public CMPRequestHolder(String requestDir) {
		super();
		this.requestDir = requestDir;
	}

	public String getRequestDir() {
		return requestDir;
	}

	public CMPRequest getCmpRequest() {
		return cmpRequest;
	}

	public void setCmpRequest(CMPRequest cmpRequest) {
		this.cmpRequest = cmpRequest;
	}

	@Override
	public void lock() {
		int holdCount = getHoldCount();
		if(holdCount>0){
			Thread owner = getOwner();
			if(owner!=null){
				String lockOwner = owner.getName();
				System.out.println("lockOwner: " + lockOwner);
			}
		}		
		super.lock();
	}

	@Override
	public void unlock() {
		int holdCount = getHoldCount();
		if(holdCount>1){
			Thread owner = getOwner();
			if(owner!=null){
				String lockOwner = owner.getName();
				System.out.println("lockOwner: " + lockOwner);
			}
		}
		super.unlock();
	}
	
	
}
