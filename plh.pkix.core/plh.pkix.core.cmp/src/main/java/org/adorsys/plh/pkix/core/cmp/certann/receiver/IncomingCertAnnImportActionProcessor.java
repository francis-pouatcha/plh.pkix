package org.adorsys.plh.pkix.core.cmp.certann.receiver;

import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertImportResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1MessageBundles;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;

public class IncomingCertAnnImportActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(IncomingCertAnnImportActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		checker.checkNull(actionContext);
		
		UserAccount userAccount = actionContext.get(UserAccount.class);
		IncomingRequests requests = actionContext.get(IncomingRequests.class);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		checker.checkNull(cmpRequest,requests, userAccount);
		
		ASN1OctetString transactionID = cmpRequest.getTransactionID();
		requests.lock(cmpRequest);
		try {
			// import certificate and chain.
			ASN1CertImportResult importResult = null;
			PKIMessage pkiMessage = requests.loadRequest(cmpRequest);
			PKIBody pkiBody = pkiMessage.getBody();
			CMPCertificate cmpCertificate = CMPCertificate.getInstance(pkiBody.getContent());
			Certificate x509v3pkCert = cmpCertificate.getX509v3PKCert();
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(x509v3pkCert);
			importResult = new ASN1CertImportResult(x509v3pkCert, transactionID, new DERGeneralizedTime(new Date()));
			try {
				userAccount.getTrustedContactManager().addCertEntry(certificateHolder);
			} catch (PlhCheckedException e) {
				importResult.setErrors(new ASN1MessageBundles(e.getErrorMessage()));
			}

			requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SEE_DETAILS), null, importResult);
		} finally {
			requests.unlock(cmpRequest);
		}
	}
}
