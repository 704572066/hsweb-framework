/*
 *  Copyright 2020 http://www.hswebframework.org
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package org.hswebframework.web.authorization.events;

import java.util.function.Function;

/**
 * 在进行授权时的最开始,触发此事件进行用户名密码解码,解码后请调用{@link #setUsername(String)} {@link #setPassword(String)}重新设置用户名密码
 *
 * @author zhouhao
 * @since 3.0
 */
public class AuthorizationDecodeEvent extends AbstractAuthorizationEvent {

    private static final long serialVersionUID = 5418501934490174251L;

    public AuthorizationDecodeEvent(String username, String password, String cid, String code, Function<String, Object> parameterGetter) {
        super(username, password, cid, code, parameterGetter);
    }

    public void setUsername(String username) {
        super.username = username;
    }

    public void setPassword(String password) {
        super.password = password;
    }

    public void setCid(String cid) {
        super.cid = cid;
    }

    public void setCode(String code) {
        super.code = code;
    }

}
