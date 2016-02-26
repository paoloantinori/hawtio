package io.hawt.osgi.jmx;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class Activator implements BundleActivator {

    private OSGiTools osgiTools;
    private ConfigAdmin configAdmin;
    private RBACRegistry rbacRegistry;

    @Override
    public void start(BundleContext context) throws Exception {
        osgiTools = new OSGiTools(context);
        osgiTools.init();

        configAdmin = new ConfigAdmin(context);
        configAdmin.init();

        rbacRegistry = new RBACRegistry(context);
        rbacRegistry.init();
    }

    @Override
    public void stop(BundleContext context) throws Exception {
        rbacRegistry.destroy();
        configAdmin.destroy();
        osgiTools.destroy();
    }

}
