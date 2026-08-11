package org.apereo.cas.config;

import org.apereo.cas.protocol.ProtocolFinalResponsePolicy;
import org.apereo.cas.test.CasTestExtension;
import org.apereo.cas.util.spring.boot.SpringBootTestAutoConfigurations;
import org.apereo.cas.web.support.ProtocolFinalResponsePolicyEnforcer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that the CAS core web auto-configuration does not opt an application
 * into authoritative final-response handling without an explicit policy.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("Web")
@ExtendWith(CasTestExtension.class)
@SpringBootTestAutoConfigurations
@SpringBootTest(classes = CasCoreWebAutoConfiguration.class)
class CasCoreWebFinalResponsePolicyTests {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void verifyUpstreamBehaviorRemainsActiveWithoutAuthoritativePolicy() {
        assertTrue(applicationContext.getBeansOfType(
            ProtocolFinalResponsePolicy.class).isEmpty());
        assertFalse(ProtocolFinalResponsePolicyEnforcer.isPolicyConfigured(
            applicationContext));
    }

    @Test
    void verifyExplicitAuthoritativePolicyEnablesFinalResponseHandling() {
        try (var context = new GenericApplicationContext()) {
            context.setParent(applicationContext);
            context.registerBean(
                ProtocolFinalResponsePolicy.BEAN_NAME,
                ProtocolFinalResponsePolicy.class,
                ProtocolFinalResponsePolicy::noOp);
            context.refresh();

            assertTrue(ProtocolFinalResponsePolicyEnforcer.isPolicyConfigured(
                context));
        }
    }
}
