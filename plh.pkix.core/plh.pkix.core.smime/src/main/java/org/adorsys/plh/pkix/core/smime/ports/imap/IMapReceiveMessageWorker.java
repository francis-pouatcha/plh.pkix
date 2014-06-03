package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.security.KeyStore.PrivateKeyEntry;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.mail.FetchProfile;
import javax.mail.Flags;
import javax.mail.FolderClosedException;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.StoreClosedException;

import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.ports.imap.IMapServer.FolderImpl;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias.PurposeEnum;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

import com.sun.mail.imap.IMAPFolder.FetchProfileItem;

public class IMapReceiveMessageWorker implements Runnable {

	private static final String PROCESSING = "PROCESSING";
	private static final String PROCESSED = "PROCESSED";

	private final EmailSynchDAO emailSynchDAO;
	private final UserAccount userAccount;

	private final int batchSize = 100;

	private final FolderImpl inboxFolder;
	private final FolderImpl ploohInFolder;
	
	public IMapReceiveMessageWorker(EmailAccountConfig emailAccountConfig) {
		this.emailSynchDAO = emailAccountConfig.getEmailSynchDAO();
		this.userAccount = emailAccountConfig.getUserAccount();
		this.inboxFolder = emailAccountConfig.getInboxFolder();
		this.ploohInFolder = emailAccountConfig.getPloohInFolder();
	}

	@Override
	public void run() {
		try {
			List<PrivateKeyEntry> privateKeyEntries = userAccount.findAllMessagePrivateKeyEntries();

			long lastMessageUid = readLastMessageUid();

			int msgnum = 1;
			if(lastMessageUid>-1){
				msgnum = findMessageWithLowerUid(lastMessageUid);
			} else {
				msgnum = findMessageReceivedFromDate();
			}
			if(msgnum<=-1) msgnum=1;

			int start = msgnum;
			int messageCount = inboxFolder.open().getMessageCount();
			
			while (start<messageCount){
	
				Message[] messages = inboxFolder.open().getMessages(start, start + batchSize);
				LinkedList<Message> messagesToReceive = new LinkedList<Message>();
				for (Message message : messages) {
					long currentMessageUid = inboxFolder.getFolder().getUID(
							message);
					if (currentMessageUid <= lastMessageUid)
						continue;
	
					messagesToReceive.add(message);
				}
				receiveMessage(messagesToReceive, privateKeyEntries);
				start = start+batchSize+1;
			}
		} catch (MessagingException m) {
			boolean closedFodlerStore =
			m instanceof FolderClosedException || m instanceof StoreClosedException;
			if(!closedFodlerStore){
				throw new IllegalStateException(m);
			}
		}
	}

	private void receiveMessage(LinkedList<Message> messagesToReceive, List<PrivateKeyEntry> privateKeyEntries) throws MessagingException {
		
		if(messagesToReceive.isEmpty()) return;

		// Read the last stand of the synchronization from the local storage.
		// Extract the last message uid we processed.
		EmailSynchData emailSynchData = emailSynchDAO.getEmailSynchData();
		emailSynchData.setLastSynchDate(new DERGeneralizedTime(new Date()));
		emailSynchData.setLastUidValidity(new ASN1Integer(inboxFolder.getFolder().getUIDValidity()));
		emailSynchData.setLasSyncState(new DERIA5String(PROCESSING));		
		emailSynchDAO.save();
		ProcessingValueHolder processingValueHolder = new ProcessingValueHolder();
		
		Message[] msgs = messagesToReceive.toArray(new Message[messagesToReceive.size()]);
		FetchProfile fp = new FetchProfile();
		fp.add(FetchProfileItem.HEADERS);
		inboxFolder.getFolder().fetch(msgs, fp);

		LinkedList<Message> messagesToProcess = new LinkedList<Message>();
		Map<String, PrivateKeyEntry> privateKeyMap = new HashMap<String, PrivateKeyEntry>();
		for (int i = 0; i < msgs.length; i++) {
			Message msg = msgs[i];
			
			long uid = inboxFolder.getFolder().getUID(msg);
			Date receivedDate = msg.getReceivedDate();
			processingValueHolder.process(receivedDate, uid);
			
			String[] recPubHeader = msg.getHeader(PloohMessageHeaders.X_RECEIVER_PUB);
			if(recPubHeader==null || recPubHeader.length==0) continue;
			PrivateKeyEntry privateKeyEntry = null;
			for (int j = 0; j < recPubHeader.length; j++) {
				String receiver_pub =  recPubHeader[j];
				privateKeyEntry = privateKeyMap.get(receiver_pub);
				if(privateKeyEntry==null){
					KeyStoreAlias keyStoreAlias = new KeyStoreAlias(receiver_pub, null, null, PurposeEnum.ME, PrivateKeyEntry.class);
					List<PrivateKeyEntry> privateKeys = userAccount.findPrivateKeys(keyStoreAlias);
					if(privateKeys.isEmpty()){
						privateKeyEntry = privateKeys.iterator().next();
						privateKeyMap.put(receiver_pub, privateKeyEntry);
					}
				}
			}
			if(privateKeyEntry!=null)messagesToProcess.add(msg);
		}
		
		processReceivedMessage(messagesToProcess, processingValueHolder);
	}

	private void processReceivedMessage(LinkedList<Message> messagesToProcess, ProcessingValueHolder processingValueHolder) throws MessagingException {
		if(messagesToProcess.isEmpty()) return;
		Message[] msgs = messagesToProcess.toArray(new Message[messagesToProcess.size()]);
		inboxFolder.getFolder().copyMessages(msgs, ploohInFolder.getFolder());
		inboxFolder.getFolder().setFlags(msgs, new Flags(Flags.Flag.DELETED), true);
		inboxFolder.closeFolder();
		ploohInFolder.closeFolder();
		EmailSynchData emailSynchData = emailSynchDAO.getEmailSynchData();
		emailSynchData.setLastProcessedUid(new ASN1Integer(processingValueHolder.getL()));
		emailSynchData.setLasSyncState(new DERIA5String(PROCESSED));	
		emailSynchData.setLastProcessedDate(new DERGeneralizedTime(processingValueHolder.getD()));
		emailSynchDAO.save();
	}

	/**
	 * Returns -1 if the current uidvalidity has changed. If not the last
	 * message uid.
	 * 
	 * @param imapFolder
	 * @return
	 */
	private long readLastMessageUid() throws MessagingException{
		// Read the last stand of the synchronization from the local storage.
		// Extract the last message uid we processed.
		EmailSynchData emailSynchData = emailSynchDAO.getEmailSynchData();
		ASN1Integer lastUidValidity = emailSynchData.getLastUidValidity();
		long lastMessageUid = -1;
		if (lastUidValidity != null) {
			long uidValidity = lastUidValidity.getValue().longValue();
			long currentUidValidity = -1;
			currentUidValidity = inboxFolder.getFolder().getUIDValidity();

			if (uidValidity == currentUidValidity) {
				ASN1Integer lastProcessedUid = emailSynchData
						.getLastProcessedUid();
				if (lastProcessedUid != null) {
					lastMessageUid = lastProcessedUid.getValue().longValue();
				}
			}
		}
		return lastMessageUid;
	}

	/*
	 * Return the msgNumber of the messages non processed by the client.
	 */
	private int findMessageWithLowerUid(long lastMessageUid)
			throws MessagingException {

		int messageCount = inboxFolder.open().getMessageCount();
		if (messageCount <= 0)
			return -1;

		// no last message uid. Return 1 and process all messages.
		if (lastMessageUid <= -1)
			return -1;

		/*
		 * We had the last message uid. first check if folder contains message
		 * with the given uid.
		 */
		Message m = inboxFolder.getFolder().getMessageByUID(lastMessageUid);
		if (m != null) {
			return m.getMessageNumber();
		}

		// uid no longer available. Iterate till we find a message with a lower
		// uid.
		int highestMessage = messageCount;
		int batchEnd = highestMessage - batchSize;
		int firstMessage = Math.max(1, batchEnd);

		while (batchEnd > 1) {
			Message[] messages = inboxFolder.getFolder().getMessages(
					firstMessage, highestMessage);
			for (Message message : messages) {
				long messageUid = inboxFolder.getFolder().getUID(message);

				/*
				 * If the first message is newer, all subsequent messages are
				 * newer.
				 */
				if (messageUid > lastMessageUid)
					break;

				if (messageUid < lastMessageUid)
					continue;

				return message.getMessageNumber();
			}
			highestMessage = firstMessage;
			batchEnd = highestMessage - batchSize;
			firstMessage = Math.max(1, batchEnd);
		}
		return -1;
	}

	/*
	 * Return the msgNumber of the messages non processed by the client.
	 */
	private int findMessageReceivedFromDate()
			throws MessagingException {

		Date startDate = null;
		EmailSynchData emailSynchData = emailSynchDAO.getEmailSynchData();
		DERGeneralizedTime lastProcessedDate = emailSynchData.getLastProcessedDate();
		try {
			startDate = lastProcessedDate.getDate();
		} catch (ParseException e) {
			throw new IllegalStateException(e);
		}
		

		int messageCount = inboxFolder.open().getMessageCount();
		if (messageCount <= 0)
			return -1;

		// uid no longer available. Iterate till we find a message with a lower
		// uid.
		int highestMessage = messageCount;
		int batchEnd = highestMessage - batchSize;
		int firstMessage = Math.max(1, batchEnd);

		while (batchEnd > 1) {
			Message[] messages = inboxFolder.getFolder().getMessages(
					firstMessage, highestMessage);
			for (Message message : messages) {
				Date receivedDate = message.getReceivedDate();
				if(receivedDate.before(startDate))
					return message.getMessageNumber();
			}
			highestMessage = firstMessage;
			batchEnd = highestMessage - batchSize;
			firstMessage = Math.max(1, batchEnd);
		}
		return -1;
	}
	
}
