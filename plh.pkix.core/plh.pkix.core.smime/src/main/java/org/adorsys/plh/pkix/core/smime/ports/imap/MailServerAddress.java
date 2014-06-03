package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.Map;

public class MailServerAddress {

	private int smtpPort = 25;
	private int smtpsPort=465; 

	private int imapPort = 143;
	private int imapsPort = 993;
	private int imap4sslPort = 585;
	
	private int pop3Port = 110;
	private int pop3sPort = 995;
	
	private String domain;//	"adorsys.de", 
	private String imapAddress; //"mail.adorsys.de", 
	private String smtpAddress; //"mail.adorsys.de",
	private String pop3Address;
	
	
	public int getSmtpPort() {
		return smtpPort;
	}
	public MailServerAddress setSmtpPort(int smtpPort) {
		this.smtpPort = smtpPort;
		return this;
	}
	public int getSmtpsPort() {
		return smtpsPort;
	}
	public MailServerAddress setSmtpsPort(int smtpsPort) {
		this.smtpsPort = smtpsPort;
		return this;
	}
	public int getImapPort() {
		return imapPort;
	}
	public MailServerAddress setImapPort(int imapPort) {
		this.imapPort = imapPort;
		return this;
	}
	public int getImapsPort() {
		return imapsPort;
	}
	public MailServerAddress setImapsPort(int imapsPort) {
		this.imapsPort = imapsPort;
		return this;
	}
	public int getImap4sslPort() {
		return imap4sslPort;
	}
	public MailServerAddress setImap4sslPort(int imap4sslPort) {
		this.imap4sslPort = imap4sslPort;
		return this;
	}
	public int getPop3Port() {
		return pop3Port;
	}
	public MailServerAddress setPop3Port(int pop3Port) {
		this.pop3Port = pop3Port;
		return this;
	}
	public int getPop3sPort() {
		return pop3sPort;
	}
	public MailServerAddress setPop3sPort(int pop3sPort) {
		this.pop3sPort = pop3sPort;
		return this;
	}
	public String getDomain() {
		return domain;
	}
	public MailServerAddress setDomain(String domain) {
		this.domain = domain;
		return this;
	}
	public String getImapAddress() {
		return imapAddress;
	}
	public MailServerAddress setImapAddress(String imapAddress) {
		this.imapAddress = imapAddress;
		return this;
	}
	public String getSmtpAddress() {
		return smtpAddress;
	}
	public MailServerAddress setSmtpAddress(String smtpAddress) {
		this.smtpAddress = smtpAddress;
		return this;
	}
	public String getPop3Address() {
		return pop3Address;
	}
	public MailServerAddress setPop3Address(String pop3Address) {
		this.pop3Address = pop3Address;
		return this;
	}
	
	public void putIn(Map<String, MailServerAddress> map){
		map.put(domain, this);
	}
}
