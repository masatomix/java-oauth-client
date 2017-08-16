package nu.mine.kino;

import static nu.mine.kino.Constants.*;
import static nu.mine.kino.utils.JSONUtils.*;
import static nu.mine.kino.utils.Utils.*;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;
import java.util.ResourceBundle;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.Client;
import javax.ws.rs.core.MediaType;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.extern.slf4j.Slf4j;
import nu.mine.kino.utils.Utils;;

/**
 * Servlet implementation class RedirectServlet
 */
// @WebServlet("/RedirectServlet")
@Slf4j
public class RedirectServlet extends HttpServlet {
    private static final long serialVersionUID = -4054957515370180691L;

    private ResourceBundle bundle = null;

    private static final String PARAM_AUTHORIZATION_CODE = "code";

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String propertyFile = getServletConfig().getInitParameter("property");
        try {
            bundle = ResourceBundle.getBundle(propertyFile);
            doSettings(bundle);
        } catch (java.util.MissingResourceException e) {
            String message = "設定ファイルが存在しません。クラスパス上に {}.propertiesを配置してください。({})";
            log.error(message, propertyFile, e.getMessage());
            throw new ServletException(e);
        }
    }

    private void doSettings(ResourceBundle bundle) {
        Enumeration<String> keys = bundle.getKeys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            log.debug("key[{}]:{}", key, bundle.getString(key));
        }
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {

        String redirect_url = getRedirect_url(request);
        String encodedRedirectUrl = URLEncoder.encode(redirect_url, "UTF-8");
        log.debug("redirect_url:[{}]", redirect_url);// ココでセットするURLは、通常OAuthサーバ側に登録されているURLでなければならない。

        String client_id = bundle.getString("client_id");
        String client_secret = bundle.getString("client_secret");

        String authorization_endpoint = bundle
                .getString("authorization_endpoint");
        String token_endpoint = bundle.getString("token_endpoint");

        String userinfo_endpoint = bundle.getString("userinfo_endpoint");
        String jwks_uri = bundle.getString("jwks_uri");

        String authorizationCode = request
                .getParameter(PARAM_AUTHORIZATION_CODE);

        if (authorizationCode == null) {
            // Authorization Codeの取得開始。

            String oauth_server_url_format = authorization_endpoint //
                    + "?" //
                    + "client_id=%1$s&" //
                    + "redirect_uri=%2$s&" //
                    + "state=%3$s&" //
                    + "nonce=%4$s&" //
                    + "response_type=%5$s&"//
                    + "scope=%6$s";

            // CSRF対策のための、stateを設定
            String state = getRandomString();

            String nonce = getRandomString();
            String response_type = "code";
            String scope =  getScope();

            String oauth_server_url = String.format(oauth_server_url_format,
                    client_id, //
                    encodedRedirectUrl, //
                    state, //
                    nonce, //
                    response_type, //
                    scope);
            log.debug(oauth_server_url);

            HttpSession session = request.getSession(true);
            log.debug("はじめのsession id: {}", session.getId());
            log.debug("session state: {}", state);
            session.setAttribute(SESSION_STATE, state);
            session.setAttribute(SESSION_NONCE, nonce);

            // OAuth Serverへリダイレクト
            response.sendRedirect(oauth_server_url);

        } else {
            // Access TokenとID Tokenの取得処理

            // CSRF対策のための、パラメタから取得したヤツと、Sessionにあるヤツの値を確認
            checkCSRF(request);

            Client client = Utils
                    .createSecureClient("http://client.example.com:8888");
            String result = getAccessTokenJSON(token_endpoint, redirect_url,
                    client_id, client_secret, authorizationCode, client);

            try {
                Map<String, Object> map = json2Map(result);
                String key = getAccess_token_key();

                String accessToken = (String) map.get(key);
                String id_token = (String) map.get("id_token");

                log.debug("access_token: {}", accessToken);
                log.debug("refresh_token: {}", map.get("refresh_token"));
                log.debug("id_token: {}", id_token);

                response.setContentType("text/plain;charset=UTF-8");
                PrintWriter out = response.getWriter();
                out.append("AccessToken: \n");
                out.append(toPrettyStr(map));
                out.append("\n\n");

                // OpenID Connect対応でないと、id_tokenが返ってこない場合もある。
                if (StringUtils.isNotEmpty(id_token)) {
                    printIdToken(id_token, out);
                    boolean checkResult = checkIdToken(id_token, jwks_uri,
                            client_secret);
                    out.append("署名検証結果: " + checkResult);
                }
                out.append("\n\n");

                // 基本このチェック不要だけど、一応入れてる。(OpenID Connectでない場合はもしかしたら独自仕様の場合アリ)
                if (StringUtils.isNotEmpty(userinfo_endpoint)) {
                    log.debug("Userinfo Endpoint Server:{}", userinfo_endpoint);
                    String userInfoJSON = getResource(userinfo_endpoint,
                            accessToken);
                    out.append("User Information: \n");
                    out.append(toPrettyStr(json2Map(userInfoJSON)));
                }

            } catch (BadRequestException e) {
                throw new ServletException(e);
            }
        }
    }

    private String getScope() {
        String scope = bundle.getString("scope");
        return StringUtils.isNotEmpty(scope) ? scope : "openid+profile+email";
    }

    private String getAccess_token_key() {
        String access_token_key = bundle.getString("access_token_key"); // OAuthだとaccess_tokenだけど、一部のプロダクトがちがう仕様なので、可変に。
        return StringUtils.isNotEmpty(access_token_key) ? access_token_key
                : "access_token";
    }

    /**
     * はじめ、getRequestURL(request) ってやるだけだったけど、プロトコルがHTTPS → HTTPになったり
     * 直接指定したいケースが出てきたので設定すればその値になるように処理を追加した。
     * 
     * @param request
     * @return
     */
    private String getRedirect_url(HttpServletRequest request) {
        String redirect_url = bundle.getString("redirect_url");
        if (StringUtils.isNotEmpty(redirect_url)) {
            return redirect_url;
        }
        return getRequestURL(request);
    }

    private String getAccessTokenJSON(String token_endpoint,
            String redirect_url, String client_id, String client_secret,
            String authorizationCode, Client client) throws ServletException {
        String result = null;

        //////////////////////// 適当コード
        /// mediaTypeが取れたらそれで投げる。取れなかったらデフォルトで投げる、がキレイ。
        String mediaType = bundle.getString("media_type");

        // QiitaだけJSONで投げないとContent-Typeチェックでエラーになる。なぜか。
        if (StringUtils.equals(mediaType, MediaType.APPLICATION_JSON)) {
            result = Utils.getAccessTokenJSON(token_endpoint, redirect_url,
                    client_id, client_secret, authorizationCode, client,
                    MediaType.APPLICATION_JSON_TYPE);
        } else {
            result = Utils.getAccessTokenJSON(token_endpoint, redirect_url,
                    client_id, client_secret, authorizationCode, client);
        }
        return result;
    }

    private void printIdToken(String id_token, PrintWriter out)
            throws JsonProcessingException, IOException {

        String[] id_token_parts = id_token.split("\\.");

        String ID_TOKEN_HEADER = base64DecodeStr(id_token_parts[0]);
        String ID_TOKEN_PAYLOAD = base64DecodeStr(id_token_parts[1]);
        // String ID_TOKEN_SIGNATURE =
        // base64DecodeStr(id_token_parts[2]);
        log.debug("ID_TOKEN_HEADER: {}", ID_TOKEN_HEADER);
        log.debug("ID_TOKEN_PAYLOAD: {}", ID_TOKEN_PAYLOAD);
        // log.debug("ID_TOKEN_SIGNATURE: {}", ID_TOKEN_SIGNATURE);

        // ホントはPAYLOADの nonce値とSessionのnonce値の一致チェックが必要。まだやってない。

        out.append("OpenID ID TOKEN HEADER: \n");
        out.append(toPrettyStr(json2Map(ID_TOKEN_HEADER)));
        out.append("\n\n");

        out.append("OpenID ID TOKEN PAYLOAD: \n");
        out.append(toPrettyStr(json2Map(ID_TOKEN_PAYLOAD)));
        out.append("\n\n");

    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        // TODO Auto-generated method stub
        doGet(request, response);
    }

}
