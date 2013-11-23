package org.adorsys.plh.pkix.core.smime.ports.utils;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;

public class PathComponentSplitterTest {

	@Test
	public void testAbsolute() {
		List<String> pathComponents = PathComponentSplitter.toPathComponents("/plh/system/devices/dev0/public_key.asc");
		Assert.assertEquals("", pathComponents.get(0));
		Assert.assertEquals("plh", pathComponents.get(1));
		Assert.assertEquals("system", pathComponents.get(2));
		Assert.assertEquals("devices", pathComponents.get(3));
		Assert.assertEquals("dev0", pathComponents.get(4));
		Assert.assertEquals("public_key.asc", pathComponents.get(5));
	}

	@Test
	public void testRelative() {
		List<String> pathComponents = PathComponentSplitter.toPathComponents("plh/system/devices/dev0/public_key.asc");
		Assert.assertEquals("plh", pathComponents.get(0));
		Assert.assertEquals("system", pathComponents.get(1));
		Assert.assertEquals("devices", pathComponents.get(2));
		Assert.assertEquals("dev0", pathComponents.get(3));
		Assert.assertEquals("public_key.asc", pathComponents.get(4));
	}
	
}
