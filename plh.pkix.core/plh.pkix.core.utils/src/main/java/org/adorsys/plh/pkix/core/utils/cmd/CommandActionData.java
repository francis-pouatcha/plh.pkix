package org.adorsys.plh.pkix.core.utils.cmd;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;

public class CommandActionData implements ActionData {

	private ASN1Command asn1Command;

	public CommandActionData(ASN1Command asn1Command) {
		this.asn1Command = asn1Command;
	}

	public ASN1Command getAsn1Command() {
		return asn1Command;
	}
	
	public CommandActionData() {
		super();
	}

	public void setAsn1Command(ASN1Command asn1Command) {
		this.asn1Command = asn1Command;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(asn1Command, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		byte[] bs = ASN1StreamUtils.readFrom(inputStream);
		asn1Command = ASN1Command.getInstance(bs);
	}

}
