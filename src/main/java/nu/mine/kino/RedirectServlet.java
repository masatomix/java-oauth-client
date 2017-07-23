package nu.mine.kino;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;
import java.util.ResourceBundle;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.RandomStringUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

/**
 * Servlet implementation class RedirectServlet
 */
// @WebServlet("/RedirectServlet")
@Slf4j
public class RedirectServlet extends HttpServlet {
    private static final long serialVersionUID = -4054957515370180691L;

    private ResourceBundle bundle = null;

    private static final String PARAM_AUTHORIZATION_CODE = "code";

    private static final String SESSION_STATE = "state";

    private static final String PARAM_STATE = "state";

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String propertyFile = "settings";
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

        String redirect_url = getRequestURL(request);
        String encodedRedirectUrl = URLEncoder.encode(redirect_url, "UTF-8");
        log.debug("redirect_url:[{}]", redirect_url);// ココでセットするURLは、通常OAuthサーバ側に登録されているURLでなければならない。

        String client_id = bundle.getString("client_id");
        String client_secret = bundle.getString("client_secret");
        String oauth_server = bundle.getString("oauth_server");
        String resource_server = bundle.getString("resource_server");

        String authorizationCode = request
                .getParameter(PARAM_AUTHORIZATION_CODE);

        if (authorizationCode == null) {

            // CSRF対策のための、stateを設定
            String state = getRandomString();
            HttpSession session = request.getSession(true);
            log.debug("はじめのsession id: {}", session.getId());
            session.setAttribute(SESSION_STATE, state);
            log.debug("session state: {}", state);

            String oauth_server_url_format = oauth_server
                    + "/api/authorization?client_id=%1s&redirect_uri=%2s&response_type=code&state=%3s&scope=openid+profile";

            String oauth_server_url = String.format(oauth_server_url_format,
                    client_id, encodedRedirectUrl, state);
            log.debug(oauth_server_url);
            response.sendRedirect(oauth_server_url);

        } else {
            // CSRF対策のための、パラメタから取得したヤツと、Sessionにあるヤツの値を確認
            HttpSession session = request.getSession(false);
            if (session == null) {
                throw new ServletException("Bad Request");
            }

            log.debug("Redirect後のsession id: {}", session.getId());
            String requestState = request.getParameter(PARAM_STATE);
            String sessionState = (String) session.getAttribute(SESSION_STATE);
            log.debug("requestState:[{}]", requestState);
            log.debug("sessionState:[{}]", sessionState);
            if (!requestState.equals(sessionState)) {
                throw new ServletException("前回のリクエストと今回のstate値が一致しないため、エラー。");
            }

            String grant_type = "authorization_code";

            MultivaluedHashMap<String, String> formParams = new MultivaluedHashMap<String, String>();
            formParams.putSingle("client_secret", client_secret);
            formParams.putSingle("client_id", client_id);
            formParams.putSingle("grant_type", grant_type);
            formParams.putSingle("redirect_uri", redirect_url);
            formParams.putSingle("code", authorizationCode);

            try {
                log.debug("OAuthServer:{}", oauth_server);
                Response restResponse = ClientBuilder.newClient() //
                        .target(oauth_server) //
                        .path("/api/token") //
                        .request(MediaType.APPLICATION_XML_TYPE)
                        .post(Entity.entity(formParams,
                                MediaType.APPLICATION_FORM_URLENCODED_TYPE));

                String result = restResponse.readEntity(String.class);
                log.debug(result);

                Map<String, Object> map = decode(result);
                log.debug(map.get("refresh_token").toString());
                log.debug(map.get("access_token").toString());

                response.getWriter().append(map.toString());
                response.getWriter().append("\n\n");

                log.debug("Resource Server:{}", resource_server);
                Response resourceResponse = ClientBuilder.newClient() //
                        .target(resource_server) //
                        // .path("/api/country/JP") //
                        .path("/api/userinfo") //
                        .request(MediaType.APPLICATION_JSON_TYPE)
                        .header("Authorization",
                                "Bearer" + map.get("access_token").toString())
                        .get();
                response.getWriter()
                        .append(resourceResponse.readEntity(String.class));
                response.getWriter()
                        .append("\naccount information. sub is key value.");

            } catch (BadRequestException e) {
                throw new ServletException(e);
            }

        }
    }

    /**
     * Requestから リクエストURLを取得する。 AWSなどでロードバランサが SSLをほどいて
     * HTTPへ転送する場合に、request.getRequestURL がHTTPになってしまうことがあり
     * その対応として、ロードバランサ経由の場合は、"X-Forwarded-Proto"
     * ヘッダにもとのプロトコルが入っているので、ソレで置換する対応を入れた。
     * 
     * http://d.hatena.ne.jp/kusakari/20090202/1233564289
     * 
     * 
     * @param request
     * @return
     */
    private String getRequestURL(HttpServletRequest request) {

        log.debug("--------------");
        StringBuffer sb = new StringBuffer();
        Enumeration<String> headernames = request.getHeaderNames();
        while (headernames.hasMoreElements()) {
            String name = (String) headernames.nextElement();
            Enumeration<String> headervals = request.getHeaders(name);
            while (headervals.hasMoreElements()) {
                String val = (String) headervals.nextElement();
                sb.append(name);
                sb.append(":");
                sb.append(val);
                sb.append("\n");
            }
        }
        log.debug(new String(sb));
        log.debug("--------------");

        String redirect_url = new String(request.getRequestURL());
        if (request.getHeader("X-Forwarded-Proto") != null) {
            if (redirect_url.startsWith("http://")) {
                redirect_url = redirect_url.replaceFirst("http://",
                        request.getHeader("X-Forwarded-Proto") + "://");
            } else {
                redirect_url = redirect_url.replaceFirst("https://",
                        request.getHeader("X-Forwarded-Proto") + "://");
            }
        }
        return redirect_url;
    }

    private Map<String, Object> decode(String result) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(result,
                new TypeReference<Map<String, Object>>() {
                });
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

    private String getRandomString() {
        return RandomStringUtils.randomAlphanumeric(40);
    }
}
