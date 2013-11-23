package org.adorsys.plh.pkix.core.smime.ports.utils;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PathComponentSplitter {
	private static List<String> toPathComponents(File file, final List<String> pathComponents){
		if(file==null) return pathComponents;
		pathComponents.add(file.getName());
		return toPathComponents(file.getParentFile(), pathComponents);
	}
	
	public static List<String> toPathComponents(String pathname){
		if(pathname==null) return Collections.emptyList();
		File file = new File(pathname);
		List<String> pathComponents = toPathComponents(file, new ArrayList<String>());
		Collections.reverse(pathComponents);
		return pathComponents;
	}

}
