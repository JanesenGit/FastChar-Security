package com.fastchar.security.interceptor;

import com.fastchar.core.FastAction;
import com.fastchar.core.FastChar;
import com.fastchar.interfaces.IFastInterceptor;
import com.fastchar.security.FastSecurityConfig;
import com.fastchar.security.exception.FastSecurityException;
import com.fastchar.utils.FastFileUtils;
import com.fastchar.utils.FastStringUtils;

import java.io.File;
import java.util.Enumeration;
import java.util.List;
import java.util.TreeSet;

public class FastSecurityInterceptor implements IFastInterceptor {

    @Override
    public void onInterceptor(FastAction fastAction) throws Exception {
        FastSecurityConfig config = FastChar.getConfig(FastSecurityConfig.class);
        if (config.isDebug()) {
            fastAction.invoke();
            return;
        }

        if (config.isExcludeUrl(fastAction.getFastRoute().getRoute())) {
            fastAction.invoke();
            return;
        }

        if (config.isExcludeRemote(fastAction.getRemoteIp())) {
            fastAction.invoke();
            return;
        }

        if (config.getSecurityModule() != -1) {
            if (config.getSecurityModule() == FastSecurityConfig.MD5_PARAMS_SIGN) {
                FastSecurityHelper.validateMD5Sign(fastAction, config);
            } else if (config.getSecurityModule() == FastSecurityConfig.RSA_HEADER_TOKEN) {
                FastSecurityHelper.validateRSA(fastAction, config);
            } else if (config.getSecurityModule() == (FastSecurityConfig.RSA_HEADER_TOKEN | FastSecurityConfig.MD5_PARAMS_SIGN)) {
                FastSecurityHelper.validateRSA(fastAction, config);
                FastSecurityHelper.validateMD5Sign(fastAction, config);
            }
        }
        fastAction.invoke();
    }


}
