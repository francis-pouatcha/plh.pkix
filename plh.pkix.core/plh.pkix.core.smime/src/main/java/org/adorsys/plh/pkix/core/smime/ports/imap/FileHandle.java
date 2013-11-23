package org.adorsys.plh.pkix.core.smime.ports.imap;

public class FileHandle {

	/**
	 * The location of this file. Generally the IMAP folder.
	 */
	public static final String X_LOC = "X-PLH-LOC"; 
	
	/**
	 * The virtual path of this file in the location.
	 */
	public static final String X_PATH = "X-PLH-PATH";
	
	/**
	 * The uid of the message in the IMAP folder.
	 */
	public static final String X_UID = "X-PLH-UID";
	
	/**
	 * The uid version of the message in the IMAP folder.
	 */
	public static final String X_UIDV = "X-PLH-UIDV";
	
	/**
	 * The id of this file on the file system
	 */
	public static final String X_FID = "X-PLH-FID";

	/**
	 * The date this message was last appended to the folder
	 */
	public static final String X_APPENDED = "X-PLH-APPENDED";

	/**
	 * The date this file was last written to the file system.
	 */
	public static final String X_STORED = "X-PLH-STORED";
	
	private String loc;
	private String path;
	private String uid;
	private String fid;
	private String uiddValidity;
	private String appended;
	private String stored;

	public String getLoc() {
		return loc;
	}
	public FileHandle setLoc(String loc) {
		this.loc = loc;
		return this;
	}
	public String getPath() {
		return path;
	}
	public FileHandle setPath(String path) {
		this.path = path;
		return this;
	}
	public String getUid() {
		return uid;
	}
	public FileHandle setUid(String uid) {
		this.uid = uid;
		return this;
	}
	public String getFid() {
		return fid;
	}
	public FileHandle setFid(String fid) {
		this.fid = fid;
		return this;
	}
	public String getUiddValidity() {
		return uiddValidity;
	}
	public FileHandle setUiddValidity(String uiddValidity) {
		this.uiddValidity = uiddValidity;
		return this;
	}
	public String getAppended() {
		return appended;
	}
	public FileHandle setAppended(String appended) {
		this.appended = appended;
		return this;
	}
	public String getStored() {
		return stored;
	}
	public FileHandle setStored(String stored) {
		this.stored = stored;
		return this;
	}	
	
}
