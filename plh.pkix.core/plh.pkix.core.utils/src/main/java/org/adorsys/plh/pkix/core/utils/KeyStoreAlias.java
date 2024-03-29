package org.adorsys.plh.pkix.core.utils;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * This class is responsible for the construction of key store aliases. We will be using alliases for a number
 * of purpose. Among other the identification of end entities. An end entity can have many keys. We will try
 * to keep the unique identifier in the subject distinguished name of each certificate so we can easily  associate 
 * certificate with their owner.
 * 
 * Note that the unique identifier is not always the same as the public key identifier. It is generally the
 * public key identifier of the first public key ever generated for this end entity. So this information should
 * never be used to reference key's.
 * 
 * @author fpo
 *
 */
public class KeyStoreAlias {
	
	private static final String KeyIdElementSeparator = "_";
	private static final String NULL_PLACE_HOLDER = "NULL";
	
	public static enum PurposeEnum  {
		CA,ME;
	}
	
	private static final int PUBLICKEY_ID_POSITION = 0;
	private static final int ISSUER_KEY_ID_POSITION = 1;
	private static final int SERIAL_NUMBER_POSITION = 2;
	private static final int PURPOSE_POSITION = 3;
	private static final int ENTRY_TYPE_POSITION = 4;

	private final String publicKeyIdHex;
	private final String authorityKeyIdHex;
	private final String serialNumberHex;
	private final String purpose;
	private final String entryType;
	
	private final String alias;
	
	public KeyStoreAlias(X509CertificateHolder subjectCertificateHolder, Class<? extends KeyStore.Entry> klass){
		this.publicKeyIdHex = KeyIdUtils.createPublicKeyIdentifierAsString(subjectCertificateHolder);
		this.authorityKeyIdHex = KeyIdUtils.readAuthorityKeyIdentifierAsString(subjectCertificateHolder);
		this.serialNumberHex = KeyIdUtils.readSerialNumberAsString(subjectCertificateHolder);
		this.purpose = getPurposeString(subjectCertificateHolder);
		this.entryType = klass==null?NULL_PLACE_HOLDER:klass.getSimpleName();
		this.alias = toAlias();
	}
	
	
	public boolean isComplete(){
		return !alias.contains(NULL_PLACE_HOLDER);
	}
	
	private static String getPurposeString(X509CertificateHolder certHolder){
		if(V3CertificateUtils.isCaKey(certHolder)) return PurposeEnum.CA.name();
		if(V3CertificateUtils.isSmimeKey(certHolder)) return PurposeEnum.ME.name();
		return null;
	}
	
	public KeyStoreAlias(String alias){
		this.alias = alias;
		String[] split = alias.split(KeyIdElementSeparator);
		this.publicKeyIdHex = split[PUBLICKEY_ID_POSITION];
		this.authorityKeyIdHex = split[ISSUER_KEY_ID_POSITION];
		this.serialNumberHex = split[SERIAL_NUMBER_POSITION];
		this.purpose = split[PURPOSE_POSITION];
		this.entryType = split[ENTRY_TYPE_POSITION];
	}

	public KeyStoreAlias(String publicKeyIdHex,
			String authorityKeyIdHex, String serialNumberHex, PurposeEnum purpose,Class<? extends KeyStore.Entry> klass) {
		super();
		this.publicKeyIdHex = publicKeyIdHex==null?NULL_PLACE_HOLDER:publicKeyIdHex;
		this.authorityKeyIdHex = authorityKeyIdHex==null?NULL_PLACE_HOLDER:authorityKeyIdHex;
		this.serialNumberHex = serialNumberHex==null?NULL_PLACE_HOLDER:serialNumberHex;
		this.purpose = purpose==null?NULL_PLACE_HOLDER:purpose.name();
		this.entryType = klass==null?NULL_PLACE_HOLDER:klass.getSimpleName();
		this.alias = toAlias();
	}
	
	private String toAlias(){
		StringBuilder sb = new StringBuilder();
		sb
		.append(this.publicKeyIdHex).append(KeyIdElementSeparator)
		.append(this.authorityKeyIdHex).append(KeyIdElementSeparator)
		.append(this.serialNumberHex).append(KeyIdElementSeparator)
		.append(this.purpose).append(KeyIdElementSeparator)
		.append(this.entryType);
		return sb.toString();
	}
	
	public Class<? extends Entry> getEntryKlass(){
		if(NULL_PLACE_HOLDER==entryType)return null;
		if(TrustedCertificateEntry.class.getSimpleName().equals(entryType)) return TrustedCertificateEntry.class;
		if(PrivateKeyEntry.class.equals(entryType)) return PrivateKeyEntry.class;
		if(SecretKeyEntry.class.equals(entryType)) return SecretKeyEntry.class;
		return null;
	}
	public boolean getEntryKlass(Class<? extends Entry> klass){
		if(NULL_PLACE_HOLDER==entryType)return true;
		if(klass.getSimpleName().equals(entryType)) return true;
		return false;
	}

	public String getPublicKeyIdHex() {
		return publicKeyIdHex;
	}

	public String getAuthorityKeyIdHex() {
		return authorityKeyIdHex;
	}

	public String getSerialNumberHex() {
		return serialNumberHex;
	}

	public String getAlias() {
		return alias;
	}

	public String getEntryType() {
		return entryType;
	}

	public PurposeEnum getPurpose() {
		return purpose==null||NULL_PLACE_HOLDER.equals(purpose)?null:PurposeEnum.valueOf(purpose);
	}

	/**
	 * Match any non null field. Null is considered a wild card.
	 * If all fields are null, this is a blanc search.
	 * 
	 * @param a
	 * @return
	 */
	public boolean matchAny(KeyStoreAlias a){
		if(a==null) return true;
		
		if(!StringUtils.equalsIgnoreCase(NULL_PLACE_HOLDER,a.getPublicKeyIdHex()))
			return StringUtils.equalsIgnoreCase(publicKeyIdHex, a.getPublicKeyIdHex());
		
		if(!StringUtils.equalsIgnoreCase(NULL_PLACE_HOLDER,a.getAuthorityKeyIdHex()))
			return StringUtils.equalsIgnoreCase(authorityKeyIdHex, a.getAuthorityKeyIdHex());
		
		if(!StringUtils.equalsIgnoreCase(NULL_PLACE_HOLDER,a.getSerialNumberHex()))
			return StringUtils.equalsIgnoreCase(serialNumberHex, a.getSerialNumberHex());

		if(a.getPurpose()!=null)
			return StringUtils.equalsIgnoreCase(purpose, a.getPurpose().name());
		
		if(!StringUtils.equalsIgnoreCase(NULL_PLACE_HOLDER,a.getEntryType()))
			return StringUtils.equalsIgnoreCase(entryType, a.getEntryType());

		// if all field are null return true;
		return true;
	}

	public boolean matchAll(KeyStoreAlias a){
		if(a==null) return false;

		if(!StringUtils.equalsIgnoreCase(NULL_PLACE_HOLDER,a.getPublicKeyIdHex()))
			if(!StringUtils.equalsIgnoreCase(publicKeyIdHex, a.getPublicKeyIdHex()))
				return false;
		if(!StringUtils.equalsIgnoreCase(NULL_PLACE_HOLDER,a.getAuthorityKeyIdHex()))
			if(!StringUtils.equalsIgnoreCase(authorityKeyIdHex, a.getAuthorityKeyIdHex()))
				return false;
		
		if(!StringUtils.equalsIgnoreCase(NULL_PLACE_HOLDER,a.getSerialNumberHex()))
			if(!StringUtils.equalsIgnoreCase(serialNumberHex, a.getSerialNumberHex()))
				return false;
		
		if(a.getPurpose()!=null)
			if(!StringUtils.equalsIgnoreCase(purpose, a.getPurpose().name()))
				return false;
		
		if(!StringUtils.equalsIgnoreCase(NULL_PLACE_HOLDER,a.getEntryType()))
			if(!StringUtils.equalsIgnoreCase(entryType, a.getEntryType()))
				return false;

		// if all field are null return true;
		return true;
	}
	
	public static String makeKeyIdHexFragment(byte[] keyIdentifier){
		return KeyIdUtils.hexEncode(keyIdentifier);
	}
	
	public static String makeSeriaNumberFrangment(BigInteger serialNumber){
		return serialNumber.toString(16);
	}
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(Enumeration<String> aliases, X509CertificateHolder certificateHolder){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,null));
	}
	
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(List<KeyStoreAlias> aliases, X509CertificateHolder certificateHolder){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,null));
	}

	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(Enumeration<String> aliases, SubjectPublicKeyInfo subjectPublicKeyInfo){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(subjectPublicKeyInfo);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,null));
	}
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(List<KeyStoreAlias> aliases, SubjectPublicKeyInfo subjectPublicKeyInfo){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(subjectPublicKeyInfo);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,null));
	}

	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(Enumeration<String> aliases, byte[] publicKeyIdentifierBytes){
		String publicKeyIdentifier = KeyIdUtils.hexEncode(publicKeyIdentifierBytes);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,null));
	}
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(List<KeyStoreAlias> aliases, byte[] publicKeyIdentifierBytes){
		String publicKeyIdentifier = KeyIdUtils.hexEncode(publicKeyIdentifierBytes);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,null));
	}
	
	public static final List<KeyStoreAlias> selectBySerialNumber(Enumeration<String> aliases, BigInteger serialNumber){
		String seriaNumberFrangment = makeSeriaNumberFrangment(serialNumber);
		return select(aliases, new KeyStoreAlias(null,null,seriaNumberFrangment,null,null));
	}
	public static final List<KeyStoreAlias> selectBySerialNumber(List<KeyStoreAlias> aliases, BigInteger serialNumber){
		String seriaNumberFrangment = makeSeriaNumberFrangment(serialNumber);
		return select(aliases, new KeyStoreAlias(null,null,seriaNumberFrangment,null,null));
	}
	
	public static final List<KeyStoreAlias> selectByIssuerKeyIdentifier(Enumeration<String> aliases, 
			X509CertificateHolder certificateHolder){
		String authorityKeyIdHex = KeyIdUtils.readAuthorityKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(null,authorityKeyIdHex,null,null,null));
	}
	public static final List<KeyStoreAlias> selectByIssuerKeyIdentifier(List<KeyStoreAlias> aliases, 
			X509CertificateHolder certificateHolder){
		String authorityKeyIdHex = KeyIdUtils.readAuthorityKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(null,authorityKeyIdHex,null,null,null));
	}
	
	public static final List<KeyStoreAlias> select(Enumeration<String> aliases, 
			KeyStoreAlias model)
	{
		List<KeyStoreAlias> result = new ArrayList<KeyStoreAlias>();
		while (aliases.hasMoreElements()) {
			String alias = (String) aliases.nextElement();
			KeyStoreAlias keyStoreAlias = new KeyStoreAlias(alias);
			if(keyStoreAlias.matchAll(model)) result.add(keyStoreAlias);
		}
		return result;
	}

	public static final List<KeyStoreAlias> select(List<KeyStoreAlias> aliases, 
			KeyStoreAlias model)
	{
		List<KeyStoreAlias> result = new ArrayList<KeyStoreAlias>();
		for (KeyStoreAlias keyStoreAlias : aliases) {
			if(keyStoreAlias.matchAll(model)) result.add(keyStoreAlias);
		}
		return result;
	}

	//========

	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(Enumeration<String> aliases, 
			X509CertificateHolder certificateHolder, Class<? extends KeyStore.Entry> entryKlass){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,entryKlass));
	}
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(List<KeyStoreAlias> aliases, 
			X509CertificateHolder certificateHolder, Class<? extends KeyStore.Entry> entryKlass){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,entryKlass));
	}

	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(Enumeration<String> aliases, 
			SubjectPublicKeyInfo subjectPublicKeyInfo, Class<? extends KeyStore.Entry> entryKlass){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(subjectPublicKeyInfo);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,entryKlass));
	}
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(List<KeyStoreAlias> aliases, 
			SubjectPublicKeyInfo subjectPublicKeyInfo, Class<? extends KeyStore.Entry> entryKlass){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(subjectPublicKeyInfo);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,entryKlass));
	}

	
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(Enumeration<String> aliases, 
			byte[] publicKeyIdentifierBytes, Class<? extends KeyStore.Entry> entryKlass){
		String publicKeyIdentifier = KeyIdUtils.hexEncode(publicKeyIdentifierBytes);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,entryKlass));
	}
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(List<KeyStoreAlias> aliases, 
			byte[] publicKeyIdentifierBytes, Class<? extends KeyStore.Entry> entryKlass){
		String publicKeyIdentifier = KeyIdUtils.hexEncode(publicKeyIdentifierBytes);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null,entryKlass));
	}

	public static final List<KeyStoreAlias> selectBySerialNumber(Enumeration<String> aliases, 
			BigInteger serialNumber, Class<? extends KeyStore.Entry> entryKlass){
		String seriaNumberFrangment = makeSeriaNumberFrangment(serialNumber);
		return select(aliases, new KeyStoreAlias(null,null,seriaNumberFrangment,null,entryKlass));
	}
	public static final List<KeyStoreAlias> selectBySerialNumber(List<KeyStoreAlias> aliases, 
			BigInteger serialNumber, Class<? extends KeyStore.Entry> entryKlass){
		String seriaNumberFrangment = makeSeriaNumberFrangment(serialNumber);
		return select(aliases, new KeyStoreAlias(null,null,seriaNumberFrangment,null,entryKlass));
	}
	
	public static final List<KeyStoreAlias> selectByIssuerKeyIdentifier(Enumeration<String> aliases, 
			X509CertificateHolder certificateHolder, Class<? extends KeyStore.Entry> entryKlass)
	{
		String authorityKeyIdHex = KeyIdUtils.readAuthorityKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(null,authorityKeyIdHex,null,null,entryKlass));
	}
	public static final List<KeyStoreAlias> selectByIssuerKeyIdentifier(List<KeyStoreAlias> aliases, 
			X509CertificateHolder certificateHolder, Class<? extends KeyStore.Entry> entryKlass)
	{
		String authorityKeyIdHex = KeyIdUtils.readAuthorityKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(null,authorityKeyIdHex,null,null,entryKlass));
	}
	// ===========
	public static String makeKEKAlias(byte[] keyIdentifier){
		return KeyIdUtils.hexEncode(keyIdentifier);
	}

	@Override
	public String toString() {
		return "KeyStoreAlias [alias=" + alias + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((alias == null) ? 0 : alias.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		KeyStoreAlias other = (KeyStoreAlias) obj;
		if (alias == null) {
			if (other.alias != null)
				return false;
		} else if (!alias.equals(other.alias))
			return false;
		return true;
	}
	
	public boolean isSelfSigned(){
		return !StringUtils.equals(NULL_PLACE_HOLDER, publicKeyIdHex) && 
				!StringUtils.equals(NULL_PLACE_HOLDER, authorityKeyIdHex) &&
				StringUtils.equalsIgnoreCase(publicKeyIdHex, authorityKeyIdHex);
	}
	
	public boolean isEntryType(Class<? extends KeyStore.Entry> entryKlass){
		return StringUtils.equalsIgnoreCase(entryKlass.getSimpleName(), entryType);
	}
}
