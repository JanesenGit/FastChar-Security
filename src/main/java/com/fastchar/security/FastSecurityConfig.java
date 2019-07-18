package com.fastchar.security;

import com.fastchar.core.FastChar;
import com.fastchar.interfaces.IFastConfig;
import com.fastchar.security.interceptor.FastSecurityGlobalInterceptor;
import com.fastchar.security.template.FastSecurityAuto;

public class FastSecurityConfig implements IFastConfig {
    /**
     * 参数签名验证，使用MD5加密！
     */
    public static final int MD5_PARAMS_SIGN = 0x0001;

    /**
     * 在HttpHeader设置Token，使用RSA加密！
     */
    public static final int RSA_HEADER_TOKEN = 0x0002;

    private int securityModule = -1;
    private boolean debug;
    private String md5Key;
    private String rsaPassword;
    private String rsaPrivateKeyPkcs8;
    private boolean rsaInitial;


    public FastSecurityConfig() {
        FastChar.getObservable().addObserver(FastSecurityGlobalInterceptor.class);
    }

    public int getSecurityModule() {
        return securityModule;
    }

    public FastSecurityConfig setSecurityModule(int securityModule) {
        this.securityModule = securityModule;
        return this;
    }

    public String getMd5Key() {
        return md5Key;
    }

    public FastSecurityConfig setMd5Key(String md5Key) {
        this.md5Key = md5Key;
        return this;
    }

    public String getRsaPrivateKeyPkcs8() {
        return rsaPrivateKeyPkcs8;
    }

    public FastSecurityConfig setRsaPrivateKeyPkcs8(String rsaPrivateKeyPkcs8) {
        this.rsaPrivateKeyPkcs8 = rsaPrivateKeyPkcs8;
        return this;
    }

    public String getRsaPassword() {
        return rsaPassword;
    }

    public FastSecurityConfig setRsaPassword(String rsaPassword) {
        this.rsaPassword = rsaPassword;
        return this;
    }

    public boolean isRsaInitial() {
        return rsaInitial;
    }

    public FastSecurityConfig setRsaInitial(boolean rsaInitial) {
        this.rsaInitial = rsaInitial;
        return this;
    }

    public boolean isDebug() {
        return debug;
    }

    public FastSecurityConfig setDebug(boolean debug) {
        this.debug = debug;
        return this;
    }


}
