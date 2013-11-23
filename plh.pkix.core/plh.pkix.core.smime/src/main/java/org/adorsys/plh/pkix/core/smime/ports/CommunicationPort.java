package org.adorsys.plh.pkix.core.smime.ports;

import javax.mail.Session;
import javax.mail.internet.MimeMessage;

/**
 * The communication port is used to send messages to or receive messages from other parties.
 * 
 * <b>Identifying a Party</b>
 * 
 * The main identifier of a party is the public key id. This is, a party is always equivalent to a 
 * key pair.
 * 
 * Some transports might require each party to have another identifier. For example:
 * <ul>
 * 	<li>
 * 		The SMTP outgoing transport will require each party to have an email. Even though this email 
 * 		will always be specifier in the Sender header field of the MimeMessage being sent, the transport
 * 		will be checking the certificate signing the MimeMessage to carry that email address. Either in the
 * 		distinguished name field of the certificate or as part of the subjectAlternativeName fields.
 * </li>
 * <li>
 * 		The IMAP incoming transport will also require the user to provide an email address managed by the 
 * 		mailbox of the party's IMAP account.
 * </li>
 * 		<br/>Note that neither in the case of IMAP nor SMTP must the
 * 		email address be unique. This email provides the possibility to use the same email email address to
 * 		service many parties. For this reason, the framework will require each message to still carry the 
 * 		public key id of the sender in the MimeHeader. Well knowing that storing the public key id of 
 * 		the party signing a message in the MimeHeader is redundant, because each message sent though 
 * 		this framework if signed, not doing this will require each party to first download the message 
 * 		and inspect the content envelope to notice that he is not the receiver of the message.
 * </ul>
 * 
 * <b>Changing Key Pair</b>
 * 
 * In case a party changes his key pair, the party shall use a field to be defined in the certificate
 * to referred to the replaced public key id. So that peers can keep grouping massages belonging to the same
 * party.
 * 
 * If a party's key is compromised, the newer certificate must carry a revocation date, such as to allow
 * peers to keep considering messages received from that party prior to the revocation date valid.
 * 
 * <b>Storing Peer's Messages</b>
 * 
 * In order to avoid unauthentic and anti-dated messages, a party must always sign a another peer message at 
 * reception before archiving it.
 * 
 * @author fpo
 *
 */
public interface CommunicationPort {
	
	public void send(MimeMessage mimeMessage);
	
	/**
	 * Registers a message endpoint, sending a signed message to the server.
	 * 
	 * POrt will not be accepted if another endpoint with the same public key is already registered.
	 * @param endpoint
	 * @param mimeMessage
	 */
	public void registerMessageEndPoint(SMIMEMessageEndpoint endpoint, MimeMessage mimeMessage);
	
	/**
	 * Returns the default session used to create the MIME messages.
	 * 
	 * @return
	 */
	public Session getDefaultSession();
	
}
