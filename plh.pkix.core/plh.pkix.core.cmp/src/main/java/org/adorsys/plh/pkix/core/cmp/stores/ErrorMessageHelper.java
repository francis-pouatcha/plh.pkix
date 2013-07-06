package org.adorsys.plh.pkix.core.cmp.stores;

import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.i18n.ErrorBundle;

public class ErrorMessageHelper {

	public static void processError(CMPRequest request, 
			CMPRequests requests, ErrorBundle errorMessage){
		ProcessingResults<Void> processingResults = new ProcessingResults<Void>();
		processingResults.addError(errorMessage);
		ASN1ProcessingResult asn1ProcessingResult = processingResults.getASN1ProcessingResult();
		ASN1Action action = requests.loadAction(request);
		requests.setResultAndNextAction(request, asn1ProcessingResult, new DERIA5String(ProcessingStatus.ERRORS), action, null);
	}

	public static void processError(CMPRequest request, 
			CMPRequests requests, ProcessingResults<?> processingResults){
		ASN1ProcessingResult asn1ProcessingResult = processingResults.getASN1ProcessingResult();
		ASN1Action action = requests.loadAction(request);
		requests.setResultAndNextAction(request, asn1ProcessingResult, new DERIA5String(ProcessingStatus.ERRORS), action, null);
	}
	
	public static ASN1ProcessingResult getASN1ProcessingResult(ErrorBundle errorMessage){
		ProcessingResults<Void> processingResults = new ProcessingResults<Void>();
		processingResults.addError(errorMessage);
		return processingResults.getASN1ProcessingResult();
	}
}
