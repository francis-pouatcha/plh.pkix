package org.adorsys.plh.pkix.core.cmp.handler;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class PKIMessageTypeString {

    private static final Map<Integer, String> typeMap = new HashMap<Integer, String>();
    
    static {
    	typeMap.put(PKIBody.TYPE_INIT_REQ, "init_req");
        typeMap.put(PKIBody.TYPE_INIT_REP, "init_rep");;
        typeMap.put(PKIBody.TYPE_CERT_REQ, "cert_req");
        typeMap.put(PKIBody.TYPE_CERT_REP, "cert_rep");
        typeMap.put(PKIBody.TYPE_P10_CERT_REQ, "p10_cert_req");
        typeMap.put(PKIBody.TYPE_POPO_CHALL, "popo_chall");
        typeMap.put(PKIBody.TYPE_POPO_REP, "popo_rep");
        typeMap.put(PKIBody.TYPE_KEY_UPDATE_REQ, "key_update_req");
        typeMap.put(PKIBody.TYPE_KEY_UPDATE_REP, "key_update_rep");
        typeMap.put(PKIBody.TYPE_KEY_RECOVERY_REQ, "key_recovery_req");
        typeMap.put(PKIBody.TYPE_KEY_RECOVERY_REP, "key_recovery_rep");
        typeMap.put(PKIBody.TYPE_REVOCATION_REQ, "revocation_req");
        typeMap.put(PKIBody.TYPE_REVOCATION_REP, "revocation_rep");
        typeMap.put(PKIBody.TYPE_CROSS_CERT_REQ, "cross_cert_req");
        typeMap.put(PKIBody.TYPE_CROSS_CERT_REP, "cross_cert_rep");
        typeMap.put(PKIBody.TYPE_CA_KEY_UPDATE_ANN, "ca_key_update_ann");
        typeMap.put(PKIBody.TYPE_CERT_ANN, "cert_ann");
        typeMap.put(PKIBody.TYPE_REVOCATION_ANN, "revocation_ann");
        typeMap.put(PKIBody.TYPE_CRL_ANN, "crl_ann");
        typeMap.put(PKIBody.TYPE_CONFIRM, "confirm");
        typeMap.put(PKIBody.TYPE_NESTED, "nested");
        typeMap.put(PKIBody.TYPE_GEN_MSG, "gen_msg");
        typeMap.put(PKIBody.TYPE_GEN_REP, "gen_rep");
        typeMap.put(PKIBody.TYPE_ERROR, "error");
        typeMap.put(PKIBody.TYPE_CERT_CONFIRM, "cert_confirm");
        typeMap.put(PKIBody.TYPE_POLL_REQ, "poll_req");
        typeMap.put(PKIBody.TYPE_POLL_REP, "poll_rep");
    }
    
    public static String get(PKIMessage pkiMessage){
    	PKIBody body = pkiMessage.getBody();
    	if(body==null) return null;
    	return typeMap.get(body.getType());
    }
}
