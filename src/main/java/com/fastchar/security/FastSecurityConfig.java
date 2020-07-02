package com.fastchar.security;

import com.fastchar.core.FastChar;
import com.fastchar.interfaces.IFastConfig;
import com.fastchar.security.interceptor.FastSecurityGlobalInterceptor;
import com.fastchar.utils.FastFileUtils;
import com.fastchar.utils.FastStringUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * FastChar-Security 接口安全配置
 */
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
    private List<String> excludeUrls = new ArrayList<>();
    private List<String> excludeRemote = new ArrayList<>();


    public FastSecurityConfig() {
        FastChar.getObservable().addObserver(FastSecurityGlobalInterceptor.class);
    }

    /**
     * 获取安全验证码模式
     *
     * @return 模式
     */
    public int getSecurityModule() {
        return securityModule;
    }

    /**
     * 设置安全验证码模式
     *
     * @param securityModule 安全验证模式：MD5_PARAMS_SIGN 和 RSA_HEADER_TOKEN 和 MD5_PARAMS_SIGN|RSA_HEADER_TOKEN
     * @return 当前对象
     */
    public FastSecurityConfig setSecurityModule(int securityModule) {
        this.securityModule = securityModule;
        return this;
    }

    /**
     * 获取MD5密钥，安全模式为：MD5_PARAMS_SIGN 有效
     *
     * @return 字符串
     */
    public String getMd5Key() {
        return md5Key;
    }

    /**
     * 设置MD5密钥，安全模式为：MD5_PARAMS_SIGN 有效
     *
     * @param md5Key 密钥
     * @return 当前对象
     */
    public FastSecurityConfig setMd5Key(String md5Key) {
        this.md5Key = md5Key;
        return this;
    }

    /**
     * 获取RSA私钥pkcs8格式，可为.pem文件名或字符串密钥
     *
     * @return .pem文件名路径或字符串密钥
     */
    public String getRsaPrivateKeyPkcs8() {
        return rsaPrivateKeyPkcs8;
    }

    /**
     * 设置RSA私钥pkcs8格式 可为.pem文件名或字符串密钥，当为.pem文件名时该文件必须存在于/src目录下
     *
     * @param rsaPrivateKeyPkcs8 .pem文件名或字符串密钥
     * @return 当前对象
     */
    public FastSecurityConfig setRsaPrivateKeyPkcs8(String rsaPrivateKeyPkcs8) {
        if (rsaPrivateKeyPkcs8.endsWith(".pem")) {
            File privateKeyFile = new File(FastChar.getPath().getClassRootPath(), rsaPrivateKeyPkcs8);
            if (privateKeyFile.exists()) {
                StringBuilder stringBuilder = new StringBuilder();
                try {
                    List<String> strings = FastFileUtils.readLines(privateKeyFile);
                    for (String line : strings) {
                        if (line.startsWith("-")) {
                            continue;
                        }
                        stringBuilder.append(line);
                    }
                } catch (Exception ignored) {
                }
                rsaPrivateKeyPkcs8 = stringBuilder.toString();
            }
        }
        this.rsaPrivateKeyPkcs8 = rsaPrivateKeyPkcs8;
        return this;
    }

    /**
     * 获取RSA密钥
     *
     * @return 字符串
     */
    public String getRsaPassword() {
        return rsaPassword;
    }

    /**
     * 设置RSA验证的密钥，一般为MD5加密后的字符串
     *
     * @param rsaPassword 密钥
     * @return 当前对象
     */
    public FastSecurityConfig setRsaPassword(String rsaPassword) {
        this.rsaPassword = rsaPassword;
        return this;
    }

    public boolean isDebug() {
        return debug;
    }

    public FastSecurityConfig setDebug(boolean debug) {
        this.debug = debug;
        return this;
    }

    /**
     * 排除指定url不做安全验证
     *
     * @param urlPatterns 地址匹配符
     * @return 当前对象
     */
    public FastSecurityConfig excludeUrl(String... urlPatterns) {
        this.excludeUrls.addAll(Arrays.asList(urlPatterns));
        return this;
    }


    /**
     * 排除指定远程请求的接口地址不做安全验证
     *
     * @param addressPattern 远程地址匹配符
     * @return 当前对象
     */
    public FastSecurityConfig excludeRemote(String... addressPattern) {
        this.excludeRemote.addAll(Arrays.asList(addressPattern));
        return this;
    }


    /**
     * 判断url是否被排除安全验证
     *
     * @param url 路径
     * @return 布尔值
     */
    public boolean isExcludeUrl(String url) {
        for (String excludeUrl : this.excludeUrls) {
            if (FastStringUtils.matches(excludeUrl, url)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断ip地址是否被排除安全验证
     *
     * @param address ip地址
     * @return 布尔值
     */
    public boolean isExcludeRemote(String address) {
        for (String exclude : this.excludeRemote) {
            if (FastStringUtils.matches(exclude, address)) {
                return true;
            }
        }
        return false;
    }


}
