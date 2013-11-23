package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import com.sun.mail.imap.IMAPFolder;

/**
 * Polls a mail folder and calls the onMessage whenever the state of the folder changes.
 * 
 * @author fpo
 *
 */
public abstract class MailPoller implements Runnable {

    private final static int CHECK_INTERVAL = 5; 
	private final static TimeUnit timeUnit = TimeUnit.MINUTES;
    private final ScheduledExecutorService scheduledExecutorService;
    
    private ScheduledFuture<?> scheduledFuture;
    
    private IMAPFolder folder;
    private int previousCount = -1;
    private int diffCount = -1;

    public MailPoller(IMAPFolder folder, ScheduledExecutorService scheduledExecutorService) {
        this.folder = folder;
        this.scheduledExecutorService = scheduledExecutorService;
    }

    private boolean poll() {
        try {
            int newCount = folder.getMessageCount();
            if (previousCount == -1) {
            	diffCount = 0;
                previousCount = newCount;
                return false;
            } else {
                if (previousCount < newCount) {
                	diffCount = newCount - previousCount;
                    previousCount = newCount;
                    return true;
                }
                return false;
            }
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public void run() {
        if (poll())
            onNewMessage();
    }

    public void start() {
    	scheduledFuture = scheduledExecutorService.scheduleWithFixedDelay(this, CHECK_INTERVAL, CHECK_INTERVAL, timeUnit);
    }

    public void stop() {
    	scheduledFuture.cancel(true);
    }
    
    public int getDiffCount() {
    	return diffCount;
    }
    
    public void setFolder(IMAPFolder folder) {
        this.folder = folder;
    }

    public abstract void onNewMessage();
}
