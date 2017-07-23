/******************************************************************************
 * Copyright (c) 2010 Masatomi KINO and others. 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * Contributors:
 *      Masatomi KINO - initial API and implementation
 * $Id$
 ******************************************************************************/


package nu.mine.kino;

import org.eclipse.jetty.plus.webapp.EnvConfiguration;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.Configuration;
import org.eclipse.jetty.webapp.WebAppContext;
import org.eclipse.jetty.webapp.WebInfConfiguration;
import org.eclipse.jetty.webapp.WebXmlConfiguration;

/**
 * @author Masatomi KINO
 * @version $Revision$
 */
public class JavaEEContainerStarter {
    @SuppressWarnings("nls")
    public static void main(final String[] pArgs) throws Exception {
        final int port = 8082;
        final String webappDirLocation = "src/main/webapp/"; //$NON-NLS-1$

        final Server server = new Server(port);
        final WebAppContext context = new WebAppContext();
        context.setConfigurations(new Configuration[] { //
                // new AnnotationConfiguration() //
                new WebXmlConfiguration() //
                , new WebInfConfiguration() //
                // , new TagLibConfiguration() //
                // , new PlusConfiguration() //
                // , new MetaInfConfiguration() //
                // , new FragmentConfiguration() //
                , new EnvConfiguration() //
        });
        context.setContextPath("/"); //$NON-NLS-1$
        context.setDescriptor(webappDirLocation + "/WEB-INF/web.xml"); //$NON-NLS-1$
        context.setResourceBase(webappDirLocation);
        context.setParentLoaderPriority(true);

        server.setHandler(context);
        server.start();
        server.join();
    }
}