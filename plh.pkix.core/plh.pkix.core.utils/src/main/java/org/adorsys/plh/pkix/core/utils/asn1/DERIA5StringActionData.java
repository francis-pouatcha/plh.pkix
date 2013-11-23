package org.adorsys.plh.pkix.core.utils.asn1;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;
import org.bouncycastle.asn1.DERIA5String;

public class DERIA5StringActionData implements ActionData {
	private DERIA5String deria5String;

	public DERIA5StringActionData() {
	}

	public DERIA5StringActionData(DERIA5String deria5String) {
		this.deria5String = deria5String;
	}

	public DERIA5String getDeria5String() {
		return deria5String;
	}

	public void setDeria5String(DERIA5String deria5String) {
		this.deria5String = deria5String;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(deria5String, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		byte[] bs = ASN1StreamUtils.readFrom(inputStream);
		deria5String = DERIA5String.getInstance(bs);
	}

}
