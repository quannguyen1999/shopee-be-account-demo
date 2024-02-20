package com.shopee.ecommer.shopeebeaccountdemo.config;

import dev.samstevens.totp.TotpInfo;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnClass(TotpInfo.class)
@EnableConfigurationProperties(TotpProperties.class)
public class TotpAutoConfiguration {

    private TotpProperties props;

    @Autowired
    public TotpAutoConfiguration(TotpProperties props) {
        this.props = props;
    }

    @Bean
    @ConditionalOnMissingBean
    public SecretGenerator secretGenerator() {
        int length = props.getSecret().getLength();
        return new DefaultSecretGenerator(length);
    }

    @Bean
    @ConditionalOnMissingBean
    public TimeProvider timeProvider() {
        return new SystemTimeProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    public HashingAlgorithm hashingAlgorithm() {
        return HashingAlgorithm.SHA1;
    }

    @Bean
    @ConditionalOnMissingBean
    public QrDataFactory qrDataFactory(HashingAlgorithm hashingAlgorithm) {
        return new QrDataFactory(hashingAlgorithm, getCodeLength(), getTimePeriod());
    }

    @Bean
    @ConditionalOnMissingBean
    public QrGenerator qrGenerator() {
        return new ZxingPngQrGenerator();
    }

    @Bean
    @ConditionalOnMissingBean
    public CodeGenerator codeGenerator(HashingAlgorithm algorithm) {
        return new DefaultCodeGenerator(algorithm, getCodeLength());
    }

    @Bean
    @ConditionalOnMissingBean
    public CodeVerifier codeVerifier(CodeGenerator codeGenerator, TimeProvider timeProvider) {
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        verifier.setTimePeriod(getTimePeriod());
        verifier.setAllowedTimePeriodDiscrepancy(props.getTime().getDiscrepancy());

        return verifier;
    }

    @Bean
    @ConditionalOnMissingBean
    public RecoveryCodeGenerator recoveryCodeGenerator() {
        return new RecoveryCodeGenerator();
    }

    private int getCodeLength() {
        return props.getCode().getLength();
    }

    private int getTimePeriod() {
        return props.getTime().getPeriod();
    }
}
