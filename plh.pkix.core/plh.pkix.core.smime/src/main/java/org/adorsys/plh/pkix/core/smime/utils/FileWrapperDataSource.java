package org.adorsys.plh.pkix.core.smime.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.DataSource;
import javax.activation.FileTypeMap;

import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

/**
 * The FileWrapperDataSource class implements a simple DataSource object
 * that encapsulates a {@link FileWrapper}. It provides data typing services via
 * a FileTypeMap object. <p>
 *
 * <b>FileWrapperDataSource Typing Semantics</b><p>
 *
 * The FileWrapperDataSource class delegates data typing of files
 * to an object subclassed from the FileTypeMap class.
 * The <code>setFileTypeMap</code> method can be used to explicitly
 * set the FileTypeMap for an instance of FileWrapperDataSource. If no
 * FileTypeMap is set, the FileWrapperDataSource will call the FileTypeMap's
 * getDefaultFileTypeMap method to get the System's default FileTypeMap.
 *
 * @see javax.activation.DataSource
 * @see javax.activation.FileTypeMap
 * @see javax.activation.MimetypesFileTypeMap
 */
public class FileWrapperDataSource implements DataSource {

	private final FileWrapper fileWrapper;
    private FileTypeMap typeMap = null;

	public FileWrapperDataSource(FileWrapper fileWrapper) {
		this.fileWrapper = fileWrapper;
	}

	@Override
	public InputStream getInputStream() throws IOException {
		return fileWrapper.newInputStream();
	}

	@Override
	public OutputStream getOutputStream() throws IOException {
		return fileWrapper.newOutputStream();
	}

    /**
     * This method returns the MIME type of the data in the form of a
     * string. This method uses the currently installed FileTypeMap. If
     * there is no FileTypeMap explicitly set, the FileWrapperDataSource will
     * call the <code>getDefaultFileTypeMap</code> method on
     * FileTypeMap to acquire a default FileTypeMap. <i>Note: By
     * default, the FileTypeMap used will be a MimetypesFileTypeMap.</i>
     *
     * @return the MIME Type
     * @see javax.activation.FileTypeMap#getDefaultFileTypeMap
     */
	@Override
	public String getContentType() {

		if (typeMap == null)
			return fileWrapper.setFileTypeMap(FileTypeMap.getDefaultFileTypeMap()).getContentType();
		else
		    return fileWrapper.setFileTypeMap(typeMap).getContentType();
    }

	@Override
	public String getName() {
		return fileWrapper.getName();
	}

	/**
     * Set the FileTypeMap to use with this {@link FileWrapperDataSource}
     *
     * @param map The FileTypeMap for this object.
     */
    public void setFileTypeMap(FileTypeMap map) {
    	typeMap = map;
    	fileWrapper.setFileTypeMap(map);
    }

}
