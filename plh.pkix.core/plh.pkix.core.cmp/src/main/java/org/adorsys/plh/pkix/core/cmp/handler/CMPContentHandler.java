package org.adorsys.plh.pkix.core.cmp.handler;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.ActivationDataFlavor;
import javax.activation.DataContentHandler;
import javax.activation.DataSource;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.util.encoders.Base64;

public class CMPContentHandler implements DataContentHandler {
	
	public static final String CMP_CONTENT_TYPE = "application/pkixcmp";
	public static final String CMP_CONTENT_TRANSFER_ENCODING = "base64";
	public static final String CMP_CONTENT_DESCRIPTION = "the ASN.1 DER-encoded PKIX-CMP message, base64-encoded";
	private final ActivationDataFlavor adf = new ActivationDataFlavor(PKIMessage.class, CMP_CONTENT_TYPE, "PKI Message");

	@Override
	public Object getContent(DataSource ds) throws IOException {
		InputStream inputStream = ds.getInputStream();
		byte[] base64EncodedMessage = IOUtils.toByteArray(inputStream);
		byte[] asn1EncodedMessage = Base64.decode(base64EncodedMessage);
		return PKIMessage.getInstance(ASN1Primitive.fromByteArray(asn1EncodedMessage));
	}

	@Override
	public Object getTransferData(DataFlavor df, DataSource ds)
			throws UnsupportedFlavorException, IOException {
		if (adf.equals(df)) {
			return getContent(ds);
		} else {
			return null;
		}
	}

	@Override
	public DataFlavor[] getTransferDataFlavors() {
		return new DataFlavor[] { adf };
	}

	@Override
	public void writeTo(Object obj, String mimeType, OutputStream os)
			throws IOException {
		if (obj instanceof PKIMessage) {
			PKIMessage pkiMessage = (PKIMessage) obj;
			byte[] asn1EncodedMessage = pkiMessage.getEncoded();
			byte[] base64EncodedMessage = Base64.encode(asn1EncodedMessage);
			IOUtils.write(base64EncodedMessage, os);
		} else {
			throw new IOException("unknown object in writeTo " + obj);
		}
	}

}
