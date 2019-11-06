package com.fastchar.security.interceptor;

import com.fastchar.core.FastAction;
import com.fastchar.core.FastChar;
import com.fastchar.core.FastEngine;
import com.fastchar.interfaces.IFastInterceptor;
import com.fastchar.security.FastSecurityConfig;
import com.fastchar.security.annotation.AFastSecurity;

public class FastSecurityGlobalInterceptor implements IFastInterceptor {

    public void onWebStart(FastEngine engine) {
        engine.getInterceptors()
                .addBefore(FastSecurityGlobalInterceptor.class, "/*");
    }

    @Override
    public void onInterceptor(FastAction fastAction) throws Exception {
        FastSecurityConfig config = FastChar.getConfig(FastSecurityConfig.class);
        if (config.isDebug()) {
            fastAction.invoke();
            return;
        }

        int securityModule = -1;
        boolean hasSecurity = false;

        if (fastAction.getClass().isAnnotationPresent(AFastSecurity.class)) {
            AFastSecurity fastSecurity = fastAction.getClass().getAnnotation(AFastSecurity.class);
            if (fastSecurity.value() != -1) {
                securityModule = fastSecurity.value();
            }
            hasSecurity = fastSecurity.enable();
        }

        if (fastAction.getFastRoute().getMethod().isAnnotationPresent(AFastSecurity.class)) {
            AFastSecurity fastSecurity = fastAction.getFastRoute().getMethod().getAnnotation(AFastSecurity.class);
            if (fastSecurity.value() != -1) {
                securityModule = fastSecurity.value();
            }
            hasSecurity = fastSecurity.enable();
        }

        if (config.isExcludeUrl(fastAction.getFastRoute().getRoute())) {
            hasSecurity = false;
        }

        if (config.isExcludeRemote(fastAction.getRemoveIp())) {
            hasSecurity = false;
        }

        if (hasSecurity) {
            if (securityModule == -1) {
                securityModule = config.getSecurityModule();
            }
            if (securityModule== FastSecurityConfig.MD5_PARAMS_SIGN) {
                FastSecurityHelper.validateMD5Sign(fastAction, config);
            } else if (securityModule == FastSecurityConfig.RSA_HEADER_TOKEN) {
                FastSecurityHelper.validateRSA(fastAction, config);
            } else if (securityModule== (FastSecurityConfig.RSA_HEADER_TOKEN | FastSecurityConfig.MD5_PARAMS_SIGN)) {
                FastSecurityHelper.validateRSA(fastAction, config);
                FastSecurityHelper.validateMD5Sign(fastAction, config);
            }
        }
        fastAction.invoke();
    }

}
