package dk.kb.poc.webservice;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.InetAddress;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import dk.kb.poc.config.ServiceConfig;
import dk.kb.util.BuildInfoManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Listener to handle the various setups and configuration sanity checks that can be carried out at when the
 * context is deployed/initalized.
 */

public class ContextListener implements ServletContextListener {
    private final Logger log = LoggerFactory.getLogger(getClass());


    /**
     * On context initialisation this
     * i) Initialises the logging framework (logback).
     * ii) Initialises the configuration class.
     * @param sce context provided by the web server upon initialization.
     * @throws java.lang.RuntimeException if anything at all goes wrong.
     */
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        try {
            RuntimeMXBean mxBean = ManagementFactory.getRuntimeMXBean();
            if (mxBean.getInputArguments().stream().noneMatch(arg -> arg.startsWith("-Xmx"))) {
                log.warn("Java heap size (-Xmx option) is not specified. " +
                         "In stage or production this is almost always an error");
            }

            log.info("Initializing service {} {} build {} using Java {} with max heap {}MB on machine {}",
                     BuildInfoManager.getName(), BuildInfoManager.getVersion(), BuildInfoManager.getBuildTime(),
                     System.getProperty("java.version"), Runtime.getRuntime().maxMemory()/1048576,
                     InetAddress.getLocalHost().getHostName());
            InitialContext ctx = new InitialContext();
            String configFile = (String) ctx.lookup("java:/comp/env/application-config");
            log.info("configFile pattern retrieved from env application-config: '" + configFile + "'");
            //TODO this should not refer to something in template. Should we perhaps use reflection here?
            ServiceConfig.initialize(configFile);
        } catch (NamingException e) {
            throw new RuntimeException("Failed to lookup settings", e);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load settings", e);        } 
        log.info("Service initialized.");
    }


    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        log.debug("Service destroyed");
    }

}
