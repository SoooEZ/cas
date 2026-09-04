package org.apereo.cas.config;

import org.apereo.cas.redis.core.RedisAccountSecurityDeletionFenceStoreVerifier;
import org.apereo.cas.redis.core.RedisAccountSecurityKeyCodec;

import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Shared, public Redis account-security deletion-fence infrastructure.
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
@AutoConfiguration(beforeName = {
    "org.apereo.cas.config.CasRedisWebAuthnAutoConfiguration",
    "org.apereo.cas.config.CasRedisMultifactorAuthenticationTrustAutoConfiguration"
})
public class CasRedisAccountSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(RedisAccountSecurityKeyCodec.class)
    public RedisAccountSecurityKeyCodec redisAccountSecurityKeyCodec() {
        return new RedisAccountSecurityKeyCodec();
    }

    @Bean
    @ConditionalOnMissingBean(RedisAccountSecurityDeletionFenceStoreVerifier.class)
    public RedisAccountSecurityDeletionFenceStoreVerifier
        redisAccountSecurityDeletionFenceStoreVerifier(
        final ListableBeanFactory beanFactory) {
        return new RedisAccountSecurityDeletionFenceStoreVerifier(beanFactory);
    }
}
