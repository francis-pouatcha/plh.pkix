package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.Enumeration;
import java.util.UUID;

import javax.mail.internet.ParseException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * Holds Email account data.
 * 
 * @author fpo
 *
 */
public class EmailAccountData extends ASN1Object {
	
	// =========================== START REQUIRED FIELDS ===============================//
	/**
	 * This can be used to localize any dependent associated with this object in case file names are modified
	 * on the file system.
	 */
	private DERIA5String accountId = new DERIA5String(UUID.randomUUID().toString());

	/**
	 * The login name of the email account.
	 */
	private DERIA5String username;
	
	/**
	 * The password of the email account.
	 */
	private DERIA5String password;

	/**
	 * The imap host.
	 */
	private DERIA5String host;
	
	/**
	 * The port of the imap server. If -1, the the default port will be used.
	 */
	private ASN1Integer port = new ASN1Integer(-1);

	/**
	 * The protocoll. Will generally be either imap or imaps.
	 */
	private DERIA5String protocol= new DERIA5String("imaps");

	/**
	 * The default email address.
	 * 
	 * @TODO: define more email addresses.
	 */
	private DERIA5String defaultEmail;
	
	private DERIA5String smtpHost;

	private DERIA5String smtpPort = new DERIA5String("-1");

	private DERIA5String smtpProtocol = new DERIA5String("smtp");

	private Certificate serverCert;
	
	/**
	 * The inbox folder of the mail account.
	 */
	private DERIA5String inboxFolder = new DERIA5String("INBOX");
	
	/**
	 * This is the inbox folder of plooh. Message sent to plooh are moved by a plooh thread into this folder.
	 */
	private DERIA5String ploohInFolder = new DERIA5String("INBOX/PLOOH/IN");
	
	/**
	 * The out folder for plooh. Mail that are sent out by plooh are stored in this folder until deleted by the 
	 * corresponding plooh process.This is not the same like the standard outbox folder in which mails that have to be
	 * send out by the mail server are stored.
	 */
	private DERIA5String ploohOutFolder = new DERIA5String("INBOX/PLOOH/OUT");
	
	/**
	 * This is the default archive folder, in which plooh stored files that are to be archived by the user.
	 */
	private DERIA5String ploohArchiveFolder = new DERIA5String("INBOX/PLOOH/ARCHIVE");

	private DERIA5String localDir = new DERIA5String(UUID.randomUUID().toString());
	
	/**
	 * File in which the state of the mail account is stored. For example:
	 * - Last synchronization date
	 * - Last last Processed MessageIds
	 * private DERGeneralizedTime lastImport;
	 * private DERIA5String lastImportComment;
	 */
	private DERIA5String stateFile = new DERIA5String(UUID.randomUUID().toString());
	
	private ASN1Boolean advanced = DERBoolean.getInstance(false);

	// =========================== END REQUIRED FIELDS ===============================//

	public EmailAccountData(DERIA5String email, DERIA5String password) {
		this.defaultEmail = email;
		this.password = password;
		try {
			MailServers.preprocessMailAccount(this);
		} catch (ParseException e) {
			throw new IllegalStateException(e);
		}
	}
	
    private EmailAccountData(ASN1Sequence seq) {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        accountId = DERIA5String.getInstance(en.nextElement());
        username = DERIA5String.getInstance(en.nextElement());
        password = DERIA5String.getInstance(en.nextElement());
        host = DERIA5String.getInstance(en.nextElement());
        port = ASN1Integer.getInstance(en.nextElement());
        protocol = DERIA5String.getInstance(en.nextElement());
        defaultEmail = DERIA5String.getInstance(en.nextElement());
        smtpHost = DERIA5String.getInstance(en.nextElement());
        smtpPort = DERIA5String.getInstance(en.nextElement());
        smtpProtocol = DERIA5String.getInstance(en.nextElement());
        serverCert = Certificate.getInstance(en.nextElement());
        inboxFolder = DERIA5String.getInstance(en.nextElement());
        ploohInFolder = DERIA5String.getInstance(en.nextElement());
        ploohOutFolder = DERIA5String.getInstance(en.nextElement());
        ploohArchiveFolder = DERIA5String.getInstance(en.nextElement());

        localDir = DERIA5String.getInstance(en.nextElement());
        stateFile = DERIA5String.getInstance(en.nextElement());
        advanced = ASN1Boolean.getInstance(en.nextElement());
        
    }

    public static EmailAccountData getInstance(Object o)
    {
        if (o instanceof EmailAccountData)
        {
            return (EmailAccountData)o;
        }

        if (o != null)
        {
            return new EmailAccountData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

	/**
     * <pre>
     * ASN1Action ::= SEQUENCE {
     * 					accountId				DERIA5String,
     * 					username				DERIA5String,
     * 					password				DERIA5String,
     * 					host					DERIA5String,
     * 					port					ASN1Integer,
     * 					protocol				DERIA5String,
     * 					defaultEmail			DERIA5String,
     * 					smtpHost				DERIA5String,
     * 					smtpPort				DERIA5String,
     * 					smtpProtocol			DERIA5String,
     * 					serverCert				DERIA5String,
     * 					inboxFolder				DERIA5String,
     * 					ploohInFolder			DERIA5String,
     * 					ploohOutFolder			DERIA5String,
     * 					ploohArchiveFolder		DERIA5String,
     * 					localDir				DERIA5String,
     * 					stateFile				DERIA5String,
     * 					advanced				ASN1Boolean
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(accountId);
        v.add(username);
        v.add(password);
        v.add(host);
        v.add(port);
        v.add(protocol);
        v.add(defaultEmail);
        v.add(smtpHost);
        v.add(smtpPort);
        v.add(smtpProtocol);
        v.add(serverCert);
        v.add(inboxFolder);
        v.add(ploohInFolder);
        v.add(ploohOutFolder);
        v.add(ploohArchiveFolder);
        v.add(localDir);
        v.add(stateFile);
        v.add(advanced);

        return new DERSequence(v);
	}

	public DERIA5String getUsername() {
		return username;
	}

	public void setUsername(DERIA5String username) {
		this.username = username;
	}

	public DERIA5String getPassword() {
		return password;
	}

	public void setPassword(DERIA5String password) {
		this.password = password;
	}

	public DERIA5String getHost() {
		return host;
	}

	public void setHost(DERIA5String host) {
		this.host = host;
	}

	public ASN1Integer getPort() {
		return port;
	}

	public void setPort(ASN1Integer port) {
		this.port = port;
	}

	public DERIA5String getProtocol() {
		return protocol;
	}

	public void setProtocol(DERIA5String protocol) {
		this.protocol = protocol;
	}

	public DERIA5String getDefaultEmail() {
		return defaultEmail;
	}

	public void setDefaultEmail(DERIA5String defaultEmail) {
		this.defaultEmail = defaultEmail;
	}

	public DERIA5String getSmtpHost() {
		return smtpHost;
	}

	public void setSmtpHost(DERIA5String smtpHost) {
		this.smtpHost = smtpHost;
	}

	public DERIA5String getSmtpPort() {
		return smtpPort;
	}

	public void setSmtpPort(DERIA5String smtpPort) {
		this.smtpPort = smtpPort;
	}

	public DERIA5String getSmtpProtocol() {
		return smtpProtocol;
	}

	public void setSmtpProtocol(DERIA5String smtpProtocol) {
		this.smtpProtocol = smtpProtocol;
	}

	public Certificate getServerCert() {
		return serverCert;
	}

	public void setServerCert(Certificate serverCert) {
		this.serverCert = serverCert;
	}

	public DERIA5String getInboxFolder() {
		return inboxFolder;
	}

	public void setInboxFolder(DERIA5String inboxFolder) {
		this.inboxFolder = inboxFolder;
	}

	public DERIA5String getPloohInFolder() {
		return ploohInFolder;
	}

	public void setPloohInFolder(DERIA5String ploohInFolder) {
		this.ploohInFolder = ploohInFolder;
	}

	public DERIA5String getPloohOutFolder() {
		return ploohOutFolder;
	}

	public void setPloohOutFolder(DERIA5String ploohOutFolder) {
		this.ploohOutFolder = ploohOutFolder;
	}

	public DERIA5String getPloohArchiveFolder() {
		return ploohArchiveFolder;
	}

	public void setPloohArchiveFolder(DERIA5String ploohArchiveFolder) {
		this.ploohArchiveFolder = ploohArchiveFolder;
	}

	public DERIA5String getLocalDir() {
		return localDir;
	}

	public void setLocalDir(DERIA5String localDir) {
		this.localDir = localDir;
	}

	public DERIA5String getStateFile() {
		return stateFile;
	}

	public void setStateFile(DERIA5String stateFile) {
		this.stateFile = stateFile;
	}

	public DERIA5String getAccountId() {
		return accountId;
	}
	//=================================

	public String getUsernameAsString() {
		return username==null?null:username.getString();
	}

	public String getPasswordAsString() {
		return password==null?null:password.getString();
	}

	public String getHostAsString() {
		return host==null?null:host.getString();
	}

	public Long getPortAsLong() {
		return port==null?null:port.getValue().longValue();
	}

	public String getProtocolAsString() {
		return protocol==null?null:protocol.getString();
	}

	public String getDefaultEmailAsString() {
		return defaultEmail==null?null:defaultEmail.getString();
	}

	public String getSmtpHostAsString() {
		return smtpHost==null?null:smtpHost.getString();
	}

	public String getSmtpPortAsString() {
		return smtpPort==null?null:smtpPort.getString();
	}

	public String getSmtpProtocolAsString() {
		return smtpProtocol==null?null:smtpProtocol.getString();
	}

	public String getInboxFolderAsString() {
		return inboxFolder==null?null:inboxFolder.getString();
	}

	public String getPloohInFolderAsString() {
		return ploohInFolder==null?null:ploohInFolder.getString();
	}

	public String getPloohOutFolderAsString() {
		return ploohOutFolder==null?null:ploohOutFolder.getString();
	}

	public String getPloohArchiveFolderAsString() {
		return ploohArchiveFolder==null?null:ploohArchiveFolder.getString();
	}

	public String getLocalDirString() {
		return localDir==null?null:localDir.getString();
	}

	public String getStateFileString() {
		return stateFile==null?null:stateFile.getString();
	}

	public String getAccountIdString() {
		return accountId==null?null:accountId.getString();
	}
	
	// ==================================================
	public void setUsername(String username) {
		this.username = username==null?null:new DERIA5String(username);
	}

	public void setPassword(String password) {
		this.password = password==null?null:new DERIA5String(password);
	}

	public void setHost(String host) {
		this.host = host==null?null:new DERIA5String(host);
	}

	public void setPort(Long port) {
		this.port = port==null?null:new ASN1Integer(port);
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol==null?null:new DERIA5String(protocol);
	}

	public void setDefaultEmail(String defaultEmail) {
		this.defaultEmail = defaultEmail==null?null:new DERIA5String(defaultEmail);
	}

	public void setSmtpHost(String smtpHost) {
		this.smtpHost = smtpHost==null?null:new DERIA5String(smtpHost);
	}

	public void setSmtpPort(String smtpPort) {
		this.smtpPort = smtpPort==null?null:new DERIA5String(smtpPort);
	}

	public void setSmtpProtocol(String smtpProtocol) {
		this.smtpProtocol = smtpProtocol==null?null:new DERIA5String(smtpProtocol);
	}

	public void setInboxFolder(String inboxFolder) {
		this.inboxFolder = inboxFolder==null?null:new DERIA5String(inboxFolder);
	}

	public void setPloohInFolder(String ploohInFolder) {
		this.ploohInFolder = ploohInFolder==null?null:new DERIA5String(ploohInFolder);
	}

	public void setPloohOutFolder(String ploohOutFolder) {
		this.ploohOutFolder = ploohOutFolder==null?null:new DERIA5String(ploohOutFolder);
	}

	public void setPloohArchiveFolder(String ploohArchiveFolder) {
		this.ploohArchiveFolder = ploohArchiveFolder==null?null:new DERIA5String(ploohArchiveFolder);
	}

	public void setLocalDir(String localDir) {
		this.localDir = localDir==null?null:new DERIA5String(localDir);
	}

	public void setStateFile(String stateFile) {
		this.stateFile = stateFile==null?null:new DERIA5String(stateFile);
	}

	public ASN1Boolean getAdvanced() {
		return advanced;
	}

	public void setAdvanced(ASN1Boolean advanced) {
		this.advanced = advanced;
	}
	
	public boolean getAdvancedAsBoolean() {
		return advanced==null?false:advanced.isTrue();
	}

	public void setAdvanced(boolean advanced) {
		this.advanced = ASN1Boolean.getInstance(advanced);
	}
}
