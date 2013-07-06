package org.adorsys.plh.pkix.core.cmp.stores;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;
import org.adorsys.plh.pkix.core.utils.asn1.DERGeneralizedTimeUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIMessage;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

/**
 * Manages CMP requests.
 * 
 * @author francis
 *
 */
public abstract class CMPRequests {
	
	private final FileWrapper requestRootDir;

	public abstract String getRequestDir();
	
	private Cache<String, CMPRequestHolder> requestCache = CacheBuilder
			.newBuilder()
			.maximumSize(500)
			.expireAfterAccess(1, TimeUnit.HOURS)
			.build();
	
	public CMPRequests(FileWrapper accountDir) {
		this.requestRootDir = accountDir.newChild(getRequestDir());
	}
	
	/**
	 * Create a new CMPRequest. First check if a request with the same transaction id exists.
	 * @param request
	 */
	public void newRequest(CMPRequest request){
		String dirName = makeRequestDir(request);

		
		 // Check existence of request in cache
		CMPRequestHolder requestHolder = requestCache.getIfPresent(dirName);
		if(requestHolder!=null && requestHolder.getCmpRequest()!=null)
			throw PlhUncheckedException.toException(new IllegalStateException("request with trasaction id exist"), getClass());
			
		// CHeck existence of request on file 
		String existingRequestDirName = findRequestDir(request.getTransactionID());
		if(existingRequestDirName!=null && !existingRequestDirName.equals(dirName))
			throw PlhUncheckedException.toException(new IllegalStateException("request with trasaction id exist"), getClass());
		
		FileWrapper requestDir =  requestRootDir.newChild(dirName);
		
		// write request to file.
		storeRequest(request, requestDir);
	}

	private CMPRequestHolder loadInternal(FileWrapper requestDir){
		FileWrapper fileWrapper = requestDir.newChild(CMPRequestFileNameHelper.cmpRequestFileName);
		InputStream inputStream = fileWrapper.newInputStream();
		CMPRequest cmpRequest = CMPRequest.getInstance(ASN1StreamUtils.readFrom(inputStream));
		IOUtils.closeQuietly(inputStream);		
		
		CMPRequestHolder requestHolder = requestCache.getIfPresent(requestDir.getName());
		if(requestHolder==null){
			requestHolder = new CMPRequestHolder(requestDir.getName());
			requestCache.put(requestHolder.getRequestDir(), requestHolder);
		}
		requestHolder.setCmpRequest(cmpRequest);
		return requestHolder;
		
	}
	
	public CMPRequest loadRequest(ASN1OctetString transactionID){
		FileWrapper requestDir = existingRequest(transactionID);
		if(requestDir==null) return null;
		CMPRequestHolder requestHolder = loadRequestHolder(requestDir);
		if(requestHolder!=null) return requestHolder.getCmpRequest();
		return null;
	}

	public CMPRequest loadRequest(int messageType, String workflowId){
		FileWrapper requestDir = existingRequest(messageType, workflowId);
		if(requestDir==null) return null;
		CMPRequestHolder requestHolder = loadRequestHolder(requestDir);
		if(requestHolder!=null) return requestHolder.getCmpRequest();
		return null;
	}

	private CMPRequestHolder loadRequestHolder(FileWrapper requestDir){
		if(requestDir==null) return null;
		CMPRequestHolder requestHolder = requestCache.getIfPresent(requestDir.getName());
		if(requestHolder!=null) return requestHolder;
		return loadInternal(requestDir);
	}

	public ASN1Action loadAction(CMPRequest cmpRequest){
		ASN1OctetString nextActionId = cmpRequest.getNextActionId();
		if(nextActionId==null)return null;
		String actionFileName = KeyIdUtils.hexEncode(nextActionId) + CMPRequestFileNameHelper.actionFileSuffix;

		FileWrapper requestDir = getRequestDir(cmpRequest.getTransactionID());
		FileWrapper fileWrapper = requestDir.newChild(actionFileName);
		if(!fileWrapper.exists())return null;
		InputStream inputStream = fileWrapper.newInputStream();
		ASN1Action asn1Action = ASN1Action.getInstance(ASN1StreamUtils.readFrom(inputStream));
		IOUtils.closeQuietly(inputStream);
		return asn1Action;
	}

	public byte[] loadActionData(CMPRequest cmpRequest){
		ASN1OctetString nextActionId = cmpRequest.getNextActionId();
		if(nextActionId==null)return null;
		String actionFileName = KeyIdUtils.hexEncode(nextActionId) + CMPRequestFileNameHelper.actionDataFileSuffix;

		FileWrapper requestDir = getRequestDir(cmpRequest.getTransactionID());
		FileWrapper fileWrapper = requestDir.newChild(actionFileName);
		if(!fileWrapper.exists()) return null;
		InputStream inputStream = fileWrapper.newInputStream();
		byte[] actionData = ASN1StreamUtils.readFrom(inputStream);
		IOUtils.closeQuietly(inputStream);
		return actionData;
	}

	public void setResultAndNextAction(CMPRequest request,
			ASN1ProcessingResult lastResult, DERIA5String status, ASN1Action nextAction, ASN1Object nextActionData) {
		
		FileWrapper requestDir = getRequestDir(request.getTransactionID());
		
		DERGeneralizedTime lastResultTime = null;
		
		if(lastResult!=null){
			String lastResultFileName = DERGeneralizedTimeUtils.getDate(lastResult.getCreated()).getTime() + CMPRequestFileNameHelper.resultFileSuffix;
			store0(lastResult, requestDir, lastResultFileName);
			lastResultTime = lastResult.getCreated();
		}
		
		request.setLastResult(lastResultTime);
		request.setStatus(status);

		ASN1Action previousAction = loadAction(request);
		if(previousAction!=null){
			previousAction.setResultOut(lastResultTime);
			String previousActionFileName = KeyIdUtils.hexEncode(previousAction.getActionID()) + CMPRequestFileNameHelper.actionFileSuffix;
			store0(previousAction, requestDir, previousActionFileName);
		}
		
		ASN1OctetString nextActionId = null;
		
		if(nextAction!=null){
			nextActionId=nextAction.getActionID();
			String nextActionIdPrefix = KeyIdUtils.hexEncode(nextActionId);
			String nextActionFileName = nextActionIdPrefix + CMPRequestFileNameHelper.actionFileSuffix;
			store0(nextAction, requestDir, nextActionFileName);
			if(nextActionData!=null){
				String nextActionDataFileName = nextActionIdPrefix + CMPRequestFileNameHelper.actionDataFileSuffix;
				store0(nextActionData, requestDir, nextActionDataFileName);
			}
		}
		
		request.setNextActionId(nextActionId);
		storeRequest(request, requestDir);
	}
	
	public ASN1ProcessingResult loadResult(CMPRequest cmpRequest){
		if(cmpRequest==null || cmpRequest.getLastResult()==null) return null;
		
		String lastResultFileName = DERGeneralizedTimeUtils.getDate(cmpRequest.getLastResult()).getTime() + CMPRequestFileNameHelper.resultFileSuffix;

		FileWrapper requestDir = getRequestDir(cmpRequest.getTransactionID());

		FileWrapper lastResultFile = requestDir.newChild(lastResultFileName);
		if(!lastResultFile.exists()) return null;
		
		InputStream inputStream = lastResultFile.newInputStream();
		ASN1ProcessingResult asn1ProcessingResult = ASN1ProcessingResult.getInstance(ASN1StreamUtils.readFrom(inputStream));
		IOUtils.closeQuietly(inputStream);
		return asn1ProcessingResult;
	}
	
	public void setRequest(CMPRequest request, PKIMessage requestMessage){
		FileWrapper requestDir = getRequestDir(request.getTransactionID());
		request.setRequestId(requestMessage.getHeader().getSenderNonce());
		storeRequest(request, requestDir);
		storePkiMessage(requestMessage, CMPRequestFileNameHelper.requestFileSuffix, requestDir);
	}
	
	public PKIMessage loadRequest(CMPRequest request){
		FileWrapper requestDir = getRequestDir(request.getTransactionID());
		return loadPkiMessage(request.getRequestId(), CMPRequestFileNameHelper.requestFileSuffix, requestDir);
	}

	public void setResponse(CMPRequest request, PKIMessage responseMessage){
		FileWrapper requestDir = getRequestDir(request.getTransactionID());
		request.setResponseId(responseMessage.getHeader().getSenderNonce());
		storeRequest(request, requestDir);
		storePkiMessage(responseMessage, CMPRequestFileNameHelper.responseFileSuffix, requestDir);
	}
	public PKIMessage loadResponse(CMPRequest request){
		FileWrapper requestDir = getRequestDir(request.getTransactionID());
		return loadPkiMessage(request.getResponseId(), CMPRequestFileNameHelper.responseFileSuffix, requestDir);
	}
	
	public void setLastPollRequest(CMPRequest request, PKIMessage lastPollRequest){
		FileWrapper requestDir = getRequestDir(request.getTransactionID());
		request.setLastPollReqId(lastPollRequest.getHeader().getSenderNonce());
		storeRequest(request, requestDir);
		storePkiMessage(lastPollRequest, CMPRequestFileNameHelper.pollRequestFileSuffix, requestDir);
	}
	public PKIMessage loadLastPollRequest(CMPRequest request){
		FileWrapper requestDir = getRequestDir(request.getTransactionID());
		return loadPkiMessage(request.getLastPollReqId(), CMPRequestFileNameHelper.pollRequestFileSuffix, requestDir);
	}

	public void setLastPollReply(CMPRequest request, PKIMessage lastPollReply){
		FileWrapper requestDir = getRequestDir(request.getTransactionID());
		request.setLastPollRepId(lastPollReply.getHeader().getSenderNonce());
		storeRequest(request, requestDir);
		storePkiMessage(lastPollReply, CMPRequestFileNameHelper.pollResponseFileSuffix, requestDir);
	}
	public PKIMessage loadLastPollReply(CMPRequest request){
		FileWrapper requestDir = getRequestDir(request.getTransactionID());
		return loadPkiMessage(request.getLastPollRepId(), CMPRequestFileNameHelper.pollResponseFileSuffix, requestDir);
	}
	private void storePkiMessage(PKIMessage pkiMessage, String suffix, FileWrapper requestDir){
		ASN1OctetString senderNonce = pkiMessage.getHeader().getSenderNonce();
		String messageFileName = KeyIdUtils.hexEncode(senderNonce) + suffix;
		store0(pkiMessage, requestDir, messageFileName);
	}
	private PKIMessage loadPkiMessage(ASN1OctetString senderNonce, String suffix, FileWrapper requestDir){
		if(senderNonce==null)return null;
		String requestFileName = KeyIdUtils.hexEncode(senderNonce) + suffix;
		FileWrapper fileWrapper = requestDir.newChild(requestFileName);
		InputStream inputStream = fileWrapper.newInputStream();
		PKIMessage pkiMessage = PKIMessage.getInstance(ASN1StreamUtils.readFrom(inputStream));
		IOUtils.closeQuietly(inputStream);
		return pkiMessage;
	}

	private void storeRequest(CMPRequest cmpRequest, FileWrapper existingRequestDir){
		CMPRequestHolder requestHolder = requestCache.getIfPresent(existingRequestDir.getName());
		if(requestHolder==null){
			requestHolder = new CMPRequestHolder(existingRequestDir.getName());
			requestCache.put(requestHolder.getRequestDir(), requestHolder);
		}
		requestHolder.setCmpRequest(cmpRequest);
		
		try {
			store0(cmpRequest, existingRequestDir, CMPRequestFileNameHelper.cmpRequestFileName);
		}catch(RuntimeException r){
			requestCache.invalidate(requestHolder.getRequestDir());
		}
	}
	private void store0(ASN1Object asn1Object, FileWrapper existingRequestDir, String fileName){
		FileWrapper existingCMPRequestFile = existingRequestDir.newChild(fileName);
		OutputStream outputStream = existingCMPRequestFile.newOutputStream();
		ASN1StreamUtils.writeTo(asn1Object, outputStream);
		IOUtils.closeQuietly(outputStream);
	}

	private String findRequestDir(ASN1OctetString transactionID){
		String[] children = requestRootDir.list();
		return CMPRequestFileNameHelper.find(children, transactionID);
	}
	public FileWrapper existingRequest(int messageType, String workflowId){
		String[] children = requestRootDir.list();
		String dirName = CMPRequestFileNameHelper.findByMessageTypeAndWorkflowId(children, messageType, workflowId);
		if(dirName==null)return null;
		return requestRootDir.newChild(dirName);
	}
	private FileWrapper existingRequest(ASN1OctetString transactionID){
		String[] children = requestRootDir.list();
		String dirName = CMPRequestFileNameHelper.find(children, transactionID);
		if(dirName==null)return null;
		return requestRootDir.newChild(dirName);
	}
	
	/**
	 * Get the request dir, throwing an exception if the dir does not exist.
	 * @param transactionID
	 * @return
	 */
	private FileWrapper getRequestDir(ASN1OctetString transactionID){
		String[] children = requestRootDir.list();
		String dirName = CMPRequestFileNameHelper.find(children, transactionID);
		if(dirName==null)
			throw PlhUncheckedException.toException(new IllegalStateException("Request dir non existant"), getClass());
		return requestRootDir.newChild(dirName);
	}

	public void deleteRequest(CMPRequest request){
		FileWrapper existingRequest = existingRequest(request.getTransactionID());
		if(existingRequest==null)return;
		if(existingRequest.exists()) existingRequest.delete();
	}
	
	/**
	 * Return true if the lock has been created, false otherwhise.
	 * 
	 * @param messageType
	 * @param workflowId
	 * @return
	 */
	public void lock(CMPRequest cmpRequest){
		ASN1OctetString transactionID = cmpRequest.getTransactionID();
		FileWrapper requestDir = getRequestDir(transactionID);
		CMPRequestHolder requestHolder = loadRequestHolder(requestDir);
		requestHolder.lock();
	}
	
	/**
	 * Return true is lock released.
	 * @param cmpRequest
	 * @return
	 */
	public void unlock(CMPRequest cmpRequest) {
		FileWrapper requestDir = existingRequest(cmpRequest.getTransactionID());
		if(requestDir==null)return;
		CMPRequestHolder requestHolder = requestCache.getIfPresent(requestDir.getName());
		if(requestHolder==null) return;
		requestHolder.unlock();
	}

	public CMPRequest loadRequest(ASN1Integer messageType, DERUTF8String workflowId) {
		return loadRequest(messageType.getValue().intValue(), workflowId.getString());
	}

	private String makeRequestDir(CMPRequest outgoingRequest){
		return CMPRequestFileNameHelper.makeFileName(outgoingRequest);
	}
}
