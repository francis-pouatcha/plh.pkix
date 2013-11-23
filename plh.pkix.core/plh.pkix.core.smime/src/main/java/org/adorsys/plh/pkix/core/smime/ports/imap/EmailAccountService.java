package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.mail.AuthenticationFailedException;
import javax.mail.Flags;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.event.MessageChangedListener;
import javax.mail.event.MessageCountEvent;
import javax.mail.event.MessageCountListener;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

import com.sun.mail.imap.IMAPFolder;
import com.sun.mail.imap.IMAPStore;
import com.sun.mail.imap.SortTerm;

/**
 * Provides access to an email server.
 * 
 * @author fpo
 * 
 */
public class EmailAccountService {

	private final static int CHECK_INTERVAL = 3000;
	private final static TimeUnit TIMEUNIT = TimeUnit.MILLISECONDS;

	private FileWrapper emailAccountDir;
	private EmailAccountDAO emailAccountDAO = new EmailAccountDAO(emailAccountDir);
	private EmailSynchDAO emailSynchDAO = new EmailSynchDAO(emailAccountDir);
	
	
	
	
	/**
	 * Executor for thread management.
	 */
	private final ScheduledExecutorService scheduledExecutorService;
	private ScheduledFuture<?> recurentCheck;

	private int pingFailureCount = 0;
	private int sessionFailureCount = 0;
	private boolean netConnectivity = false;


	private MessageCountListener messageCountListener, externalCountListener;
	private MessageChangedListener messageChangedListener,externalChangedListener;

	private boolean connected;
	private MailPoller poller;

	private IMAPStore server;

    private boolean useSSL;
	
	public EmailAccountService(ScheduledExecutorService scheduledExecutorService) {
		this.scheduledExecutorService = scheduledExecutorService;
	}

	public void run() {
		initConnection();
	}

	private void initConnection() {
		startNetworkCheck();

		poller = new MailPoller(folder, scheduledExecutorService) {

			@Override
			public void onNewMessage() {
				try {
					if (externalCountListener != null) {
						externalCountListener
								.messagesAdded(new MessageCountEvent(
										folder, MessageCountEvent.ADDED,
										false, getNewMessages()));
						messageCountListener
								.messagesAdded(new MessageCountEvent(
										folder, MessageCountEvent.ADDED,
										false, getNewMessages()));
					}
				} catch (Exception e) {
					onError(e);
				}

			}
		};

		Properties props = System.getProperties();

		// enable to throw out everything...
		// props.put("mail.debug", "true");

		String imapProtocol = "imap";
		if (useSSL) {
			imapProtocol = "imaps";
			props.setProperty("mail.imap.socketFactory.class",
					"javax.net.ssl.SSLSocketFactory");
			props.setProperty("mail.imap.socketFactory.fallback", "false");
		}
		props.setProperty("mail.store.protocol", imapProtocol);
		Session session = Session.getDefaultInstance(props, null);
		try {
			server = (IMAPStore) session.getStore(imapProtocol);
			connect();
		} catch (MessagingException ex) {
			onError(ex);
		}
	}

	public void connect() {
		try {
			server.connect(emailAccountData.getHostAsString(), emailAccountData.getPortAsLong().intValue(), emailAccountData.getUsernameAsString(), emailAccountData.getPasswordAsString());
			server.getFolder("INBOX");
			initStore();
			connected = true;
			onConnect();
		} catch (AuthenticationFailedException ex) {
			connected = false;
			onError(ex);
		} catch (MessagingException ex) {
			connected = false;
			folder = null;
			messageChangedListener = null;
			messageCountListener = null;
			onError(ex);
		} catch (IllegalStateException ex) {
			connected = true;
			onConnect();
		}
	}

	public void disconnect() {
		if (!connected && server == null && !server.isConnected())
			return;

		Thread t = new Thread(new Runnable() {

			public void run() {
				try {
					closeFolder();
					server.close();
					prober.stop();
					poller.stop();
					connected = false;
					onDisconnect();
				} catch (Exception e) {
					onError(e);
				}
			}
		});
		t.start();
	}

	public void initStore() throws IOException {

		Properties retrieveMailProperties = new Properties();
		MailServers.addSSLMailProperties(retrieveMailProperties);

		Session mailSession = Session.getInstance(retrieveMailProperties);
		try {
			server = (IMAPStore) mailSession.getStore(emailAccountData
					.getProtocolAsString());
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException(e);
		}

		if (emailAccountSynch == null) {
			emailAccountSynch = new EmailSynchData(
					emailAccountData.getAccountId());
		}

		try {
			server.connect(emailAccountData.getHostAsString(),
					emailAccountData.getPortAsLong().intValue(),
					emailAccountData.getUsernameAsString(), 
					emailAccountData.getPasswordAsString());
		} catch (AuthenticationFailedException au) {
			saveAndCloseStore("#{msgs.MailImportAction_UserNamePwdNotCorrect}",
					emailAccountSynch, server);
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				saveAndCloseStore("#{msgs.MailImportAction_HostUnknown}",
						emailAccountSynch, server);
			}
			saveAndCloseStore(e.getMessage(), emailAccountSynch, server);
		}
	}

	private void saveAndCloseStore(String message,
			EmailSynchData emailAccountState, Store store)
			throws IOException {
		emailAccountState.setLasSyncState(new DERIA5String(message));
		emailAccountState.setLastSynchDate(new DERGeneralizedTime(new Date()));
		saveEmailAccountState();
		closeStore(store);
		stopNetworkCheck();
	}

	public Store reconnect(EmailAccountData emailAccount, Store store)
			throws IOException {
		if (emailAccountSynch == null) {
			emailAccountSynch = new EmailSynchData(
					emailAccount.getAccountId());
		}
		try {
			store.connect(emailAccount.getHost().getString(),
					emailAccount.getPort().getPositiveValue().intValue(), 
					emailAccount.getUsername().getString(), 
					emailAccount.getPassword().getString());
		} catch (AuthenticationFailedException au) {
			saveAndCloseStore("#{msgs.MailImportAction_UserNamePwdNotCorrect}",
					emailAccountSynch, store);
			return null;
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				saveAndCloseStore("#{msgs.MailImportAction_HostUnknown}",
						emailAccountSynch, store);
				return null;
			}
			saveAndCloseStore(e.getMessage(), emailAccountSynch, store);
			return null;
		}
		return store;
	}

	private void closeStore(Store store) {
		if (store != null) {
			try {
				if (store.isConnected()) {
					store.close();
				}
			} catch (MessagingException ex) {
				throw new IllegalStateException(ex);
			}
		}
	}

	/**
	 * Returns true if the server can be reached. Store connectivity status in
	 * the flag networkConnectivity.
	 * 
	 * If while checking the server is reachable, the pingFailureCount is reset
	 * to 0. If not the pingFailureCount is increases.
	 * 
	 * @return
	 */
	private boolean networkCheck() {
		boolean status = true;
		Socket socket = null;
		try {
			socket = new Socket(emailAccountData.getHostAsString(), emailAccountData
					.getPortAsLong().intValue());
			status = true;
			pingFailureCount = 0;
		} catch (Exception ex) {
			status = false;
			pingFailureCount++;
		} finally {
			if (socket != null) {
				try {
					socket.close();
				} catch (Exception e) {
				}
			}
		}
		netConnectivity = status;
		return status;
	}

	public void startNetworkCheck() {
		sessionFailureCount = 0;
		pingFailureCount = 0;
		
		Runnable r = new Runnable(){
			@Override
			public void run() {onNetworkChange(networkCheck());}
		};
		
		recurentCheck = scheduledExecutorService.scheduleWithFixedDelay(r,
				CHECK_INTERVAL, CHECK_INTERVAL, TIMEUNIT);
	}

	public void stopNetworkCheck() {
		recurentCheck.cancel(false);
	}

	public void onNetworkChange(boolean status){
        if (status != connected) { // if two states do not match, something has truly changed!
            if (status && !connected) { // if connection up, but not connected...
                connect();
            } else if (!status && connected) { //if previously connected, but link down... then just disconnect...
                if (sessionFailureCount >= 2 || pingFailureCount >= 2) {
                    connected = false;
                    if (!usePush)
                        poller.stop();

                    onDisconnect();
                    //connect();
                }
            }
        } else { // if link (either session or net connection) and connection down, something gone wrong...
            if (!connected && netConnectivity) // need to make sure that session is down, but link is up...
                connect();
        }    	
    }

    private boolean sessionCheck() {
        boolean status = networkCheck();
        if (status) {
            if (connected) {
                sessionFailureCount = 0;
                return true;
            } else {
                sessionFailureCount++;
                return false;
            }
        }
        return false;
    }

    private void openFolder() throws MessagingException {
        if (folder == null)
            return;

        folder.open(Folder.READ_ONLY);
        folder.setSubscribed(true);
        removeAllListenersFromFolder();
        addAllListenersFromFolder();
        poller.setFolder(folder);

        if (usePush)
            usePush();
        else
            poller.start(accountName);
    }

    private void closeFolder() throws MessagingException {
        if (folder == null || !folder.isOpen())
            return;

        removeAllListenersFromFolder();
        folder.setSubscribed(false);
        folder.close(false);
        folder = null;
    }
    
    
    @Override
    public void onError(Exception e) {
        connected = false;
        handleError(this, e);
    }

    @Override
    public void onConnect() {
        connected = true;
        onStateChange();
    }

    @Override
    public void onDisconnect() {
        connected = false;
        onStateChange();
    }
    
    
}
