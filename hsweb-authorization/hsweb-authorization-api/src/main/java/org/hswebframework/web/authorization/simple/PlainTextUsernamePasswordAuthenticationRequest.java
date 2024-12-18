package org.hswebframework.web.authorization.simple;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hswebframework.web.authorization.AuthenticationRequest;

/**
 * @author zhouhao
 * @since 3.0.0-RC
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PlainTextUsernamePasswordAuthenticationRequest implements AuthenticationRequest {
    private String username;

    private String password;

    private String cid;

    private String code;

    // 自定义构造函数，设置 cid 默认值为空字符串
    public PlainTextUsernamePasswordAuthenticationRequest(String username, String password) {
        this.username = username;
        this.password = password;
        this.cid = "";  // 默认值
        this.code = ""; //默认值
    }
}
