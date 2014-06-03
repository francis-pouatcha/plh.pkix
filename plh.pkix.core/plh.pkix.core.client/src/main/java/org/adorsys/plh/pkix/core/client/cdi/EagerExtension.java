package org.adorsys.plh.pkix.core.client.cdi;

import java.util.ArrayList;
import java.util.List;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterDeploymentValidation;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessBean;

public class EagerExtension implements Extension {
	private List<Bean<?>> eagerBeansList = new ArrayList<Bean<?>>();
	private List<String> processedBeansList = new ArrayList<String>();
	 
    public <T> void collect(@Observes ProcessBean<T> event) {
        if (event.getAnnotated().isAnnotationPresent(Eager.class)) {
            eagerBeansList.add(event.getBean());
        }
    }
 
    public void load(@Observes AfterDeploymentValidation event, BeanManager beanManager) {
        for (Bean<?> bean : eagerBeansList) {
            // note: toString() is important to instantiate the bean
        	if(processedBeansList.contains(bean.getBeanClass().getName())) {
        		continue;
        	}
        	processedBeansList.add(bean.getBeanClass().getName());
            beanManager.getReference(
            		bean, bean.getBeanClass(), 
            		beanManager.createCreationalContext(bean)).toString();
        }
    }
}
