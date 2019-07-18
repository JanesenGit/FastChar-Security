package com.fastchar.security.template;

import com.fastchar.core.FastChar;
import com.fastchar.security.exception.FastSecurityException;
import com.fastchar.security.utils.RSABuilder;
import com.fastchar.utils.FastFileUtils;
import com.fastchar.utils.FastMD5Utils;
import com.fastchar.utils.FastStringUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FastSecurityAuto {

    public static String ProjectPath = null;

    private static String replacePlaceholder(Map<String, Object> placeholders, String content) {
        for (String key : placeholders.keySet()) {
            if (placeholders.get(key) != null) {
                content = content.replaceAll("\\$\\{" + key + "}", placeholders.get(key).toString());
                content = content.replaceAll("\\$\\[" + key + "]", placeholders.get(key).toString());
            }
        }
        return content;
    }


    public static void buildMd5() {
        try {
            if (FastStringUtils.isEmpty(ProjectPath)) {
                throw new FastSecurityException("项目路径不可为空！请配置FastSecurityAuto.ProjectPath值！");
            }

            String md5Key = FastMD5Utils.MD5(System.getenv().toString() + System.currentTimeMillis());
            Map<String, Object> params = new HashMap<>();
            params.put("key", md5Key);

            URL javascriptTemplate = FastSecurityAuto.class.getResource("md5_javascript");
            File javascriptFile = new File(ProjectPath, "/security/md5/fast-security.js");
            FastFileUtils.copyURLToFile(javascriptTemplate, javascriptFile);
            String javascript = FastFileUtils.readFileToString(javascriptFile, "utf-8");
            FastFileUtils.writeStringToFile(javascriptFile, replacePlaceholder(params, javascript));

            URL androidTemplate = FastSecurityAuto.class.getResource("md5_android");
            File androidFile = new File(ProjectPath, "/security/md5/android_code.txt");
            FastFileUtils.copyURLToFile(androidTemplate, androidFile);
            String android = FastFileUtils.readFileToString(androidFile, "utf-8");
            FastFileUtils.writeStringToFile(androidFile, replacePlaceholder(params, android));

            URL iosTemplate = FastSecurityAuto.class.getResource("md5_ios");
            File iosFile = new File(ProjectPath, "/security/md5/ios_code.txt");
            FastFileUtils.copyURLToFile(iosTemplate, iosFile);
            String ios = FastFileUtils.readFileToString(iosFile, "utf-8");
            FastFileUtils.writeStringToFile(iosFile, replacePlaceholder(params, ios));


            System.out.println(FastChar.getLog().lightStyle("============================FastSecurity-MD5============================"));
            System.out.println();
            System.out.println(FastChar.getLog().lightStyle("MD5加签的密钥为：" + md5Key));
            System.out.println(FastChar.getLog().lightStyle("请将MD5密钥配置到FastSecurityConfig.md5Key中！"));
            System.out.println(FastChar.getLog().lightStyle("JavaScript代码：" + javascriptFile.getAbsolutePath()));
            System.out.println(FastChar.getLog().lightStyle("JavaScript的密钥直接存在代码中，建议在进行JavaScript文件加密混淆！"));
            System.out.println(FastChar.getLog().lightStyle("在线混淆：https://javascriptobfuscator.com/Javascript-Obfuscator.aspx"));
            System.out.println(FastChar.getLog().lightStyle("Android代码：" + androidFile.getAbsolutePath()));
            System.out.println(FastChar.getLog().lightStyle("Object-C代码：" + iosFile.getAbsolutePath()));
            System.out.println();
            System.out.println(FastChar.getLog().lightStyle("============================FastSecurity-MD5============================"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void buildRsa() {
        buildRsa(1024);
    }
    public static void buildRsa(int keyLength) {
        try {
            if (FastStringUtils.isEmpty(ProjectPath)) {
                throw new FastSecurityException("项目路径不可为空！请配置FastSecurityAuto.ProjectPath值！");
            }

            String md5Key = FastMD5Utils.MD5(System.getenv().toString() + System.currentTimeMillis());
            Map<String, Object> params = new HashMap<>();
            params.put("key", md5Key);

            File publicKey = new File(ProjectPath, "security/rsa/rsa_public_"+keyLength+".pem");
            new RSABuilder()
                    .setKeyLength(keyLength)
                    .setPrivateKeyFile(new File(ProjectPath, "security/rsa/rsa_private_" + keyLength + ".pem").getAbsolutePath())
                    .setPrivateKeyPkcs8File(new File(ProjectPath, "security/rsa/rsa_private_pkcs8_" + keyLength + ".pem").getAbsolutePath())
                    .setPublicKeyFile(publicKey.getAbsolutePath())
                    .builder();

            StringBuilder stringBuilder = new StringBuilder();
            List<String> strings = FastFileUtils.readLines(publicKey);
            for (String string : strings) {
                if (string.startsWith("--")) {
                    continue;
                }
                stringBuilder.append(string);
            }
            params.put("publicKey", stringBuilder.toString());


            URL javascriptTemplate = FastSecurityAuto.class.getResource("rsa_javascript");
            File javascriptFile = new File(ProjectPath, "/security/rsa/fast-security.js");
            FastFileUtils.copyURLToFile(javascriptTemplate, javascriptFile);
            String javascript = FastFileUtils.readFileToString(javascriptFile, "utf-8");
            FastFileUtils.writeStringToFile(javascriptFile, replacePlaceholder(params, javascript));

            URL androidTemplate = FastSecurityAuto.class.getResource("rsa_android");
            File androidFile = new File(ProjectPath, "/security/rsa/android_code.txt");
            FastFileUtils.copyURLToFile(androidTemplate, androidFile);
            String android = FastFileUtils.readFileToString(androidFile, "utf-8");
            FastFileUtils.writeStringToFile(androidFile, replacePlaceholder(params, android));

            URL iosTemplate = FastSecurityAuto.class.getResource("rsa_ios");
            URL iosToolATemplate = FastSecurityAuto.class.getResource("ios_rsa.h");
            URL iosToolBTemplate = FastSecurityAuto.class.getResource("ios_rsa.m");
            File iosFile = new File(ProjectPath, "/security/rsa/ios/ios_code.txt");
            File iosToolAFile = new File(ProjectPath, "/security/rsa/ios/RSA.h");
            File iosToolMFile = new File(ProjectPath, "/security/rsa/ios/RSA.m");
            FastFileUtils.copyURLToFile(iosTemplate, iosFile);
            FastFileUtils.copyURLToFile(iosToolATemplate, iosToolAFile);
            FastFileUtils.copyURLToFile(iosToolBTemplate, iosToolMFile);
            String ios = FastFileUtils.readFileToString(iosFile, "utf-8");
            FastFileUtils.writeStringToFile(iosFile, replacePlaceholder(params, ios));

            System.out.println(FastChar.getLog().lightStyle("============================FastSecurity-RSA============================"));
            System.out.println();
            System.out.println(FastChar.getLog().lightStyle("RSA加密的密钥为：" + md5Key));
            System.out.println(FastChar.getLog().lightStyle("请将RSA密码配置到FastSecurityConfig.rsaPassword中！"));
            System.out.println(FastChar.getLog().lightStyle("请将RSA私钥pkcs8配置到FastSecurityConfig.setRsaPrivateKeyPkcs8中！"));
            System.out.println(FastChar.getLog().lightStyle("JavaScript代码：" + javascriptFile.getAbsolutePath()));
            System.out.println(FastChar.getLog().lightStyle("【重要】JavaScript的密钥直接存在代码中，建议在进行JavaScript文件加密混淆！"));
            System.out.println(FastChar.getLog().lightStyle("在线混淆：https://javascriptobfuscator.com/Javascript-Obfuscator.aspx"));
            System.out.println(FastChar.getLog().lightStyle("Android代码：" + androidFile.getAbsolutePath()));
            System.out.println(FastChar.getLog().lightStyle("Object-C代码：" + iosFile.getAbsolutePath()));
            System.out.println();
            System.out.println(FastChar.getLog().lightStyle("============================FastSecurity-RSA============================"));

        } catch (Exception e) {
            e.printStackTrace();
        }


    }


}
