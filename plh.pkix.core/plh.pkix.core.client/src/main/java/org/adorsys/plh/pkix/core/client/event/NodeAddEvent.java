package org.adorsys.plh.pkix.core.client.event;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

/**
 *	Event to add a node to a container. The type of the event object
 *	decides which container receives the event.
 *  
 * @author francis pouatcha
 *
 */
@Qualifier
@Target({ ElementType.TYPE, ElementType.METHOD, ElementType.FIELD, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
public @interface NodeAddEvent {
}
