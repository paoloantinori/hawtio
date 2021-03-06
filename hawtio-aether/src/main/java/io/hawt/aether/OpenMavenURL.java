/**
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.hawt.aether;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.JMX;
import javax.management.MBeanServer;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;

/**
 * Loads maven URLs
 */
public class OpenMavenURL {
    private static final transient Logger LOG = LoggerFactory.getLogger(OpenMavenURL.class);

    private static AetherFacade hack;
    private final String mavenCoords;

    public OpenMavenURL(String mavenCoords) {
        this.mavenCoords = mavenCoords;
    }


    public InputStream getInputStream() throws IOException {
        AetherFacadeMXBean mbean = findAetherMBean();
        String fileName = null;
        try {
            fileName = mbean.resolveUrlToFileName(mavenCoords);
        } catch (Exception e) {
            throw new IOException("Failed to resolve mvn:" + mavenCoords + ". " + e, e);
        }
        if (fileName != null) {
            File file = new File(fileName);
            if (file.isFile() && file.exists()) {
                return new FileInputStream(file);
            }
        }
        return null;
    }

    protected AetherFacadeMXBean findAetherMBean() {
        MBeanServer mBeanServer = ManagementFactory.getPlatformMBeanServer();
        if (mBeanServer != null) {
            String mbeanName = AetherFacade.AETHER_MBEAN_NAME;
            try {
                ObjectName objectName = new ObjectName(mbeanName);
                ObjectInstance objectInstance = mBeanServer.getObjectInstance(objectName);
                if (objectInstance != null) {
                    AetherFacadeMXBean aether = JMX.newMBeanProxy(mBeanServer, objectName, AetherFacadeMXBean.class);
                    if (aether != null) {
                        return aether;
                    }
                }
            } catch (Exception e) {
                LOG.warn("Could not find MBean " + mbeanName + " so using a default implementation of AetherFacadeMXBean");
            }
        } else {
            LOG.warn("No MBeanServer so using a default implementation of AetherFacadeMXBean");
        }
        if (hack == null) {
            hack = new AetherFacade();
        }
        return hack;
    }
}
