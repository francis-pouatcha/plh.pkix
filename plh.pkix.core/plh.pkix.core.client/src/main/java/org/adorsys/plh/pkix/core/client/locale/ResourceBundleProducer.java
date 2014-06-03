package org.adorsys.plh.pkix.core.client.locale;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;
import java.util.Set;

import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;

public class ResourceBundleProducer {

	@Inject
	private Locale locale;

	@Produces
	protected ResourceBundle injectableResourceBundle(
			InjectionPoint injectionPoint) {
		Bundle bundle = getBundleClass(injectionPoint.getAnnotated().getAnnotations());

		if (bundle != null) {
			Class<?>[] classes = bundle.value();

			if (classes!= null) {
				List<PropertyResourceBundle> p = new ArrayList<>();
				for (Class<?> klass : classes) {
					p.add((PropertyResourceBundle) ResourceBundle
							.getBundle(klass.getName(), locale));
				}
				return new CompoundResourceBundle(p);
			}
		}
		throw new IllegalStateException("Missing resource bundle annotation.");
	}

	private static Bundle getBundleClass(Set<Annotation> qualifiers) {
		for (Annotation qualifier : qualifiers) {
			if (Bundle.class.isAssignableFrom(qualifier.annotationType())) {
				return (Bundle) qualifier;
			}
		}
		return null;
	}
}
