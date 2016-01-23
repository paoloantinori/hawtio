package io.hawt.web;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

import io.hawt.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A helper object to store the proxy location details
 */
public class ProxyDetails {
    private static final transient Logger LOG = LoggerFactory.getLogger(ProxyDetails.class);

    private String scheme = DEFAULT_SCHEME;
    private String path = "";
    private String userName;
    private String password;
    private String host;
    private String queryString = null;
    private int port = DEFAULT_PORT;

    private static final int DEFAULT_PORT = 80;
    private static final String DEFAULT_SCHEME = "http";
    private static final int HTTPS_PORT = 443;
    private static final String HTTPS_SCHEME = "https";

    private static final Pattern pathInfoPattern = Pattern.compile("^(?:\\/*(?:(?<scheme>[^:]+):\\/\\/?)?(?:(?<username>[^:]+):(?<password>.*)@)?)?(?<host>[^\\/]+)(?:[\\/:](?<port>\\d+)?)(?<path>[^\\?]+).*$");

    private static final Pattern removeIgnoredHeaderNamesPattern = Pattern.compile("(^|(?<=[?&;]))(?:_user|_pwd|_url|url)=.*?($|[&;])");

    public ProxyDetails(HttpServletRequest httpServletRequest) {
        parsePathInfo(httpServletRequest.getPathInfo());

        // lets add the query parameters
        String reqQueryString = httpServletRequest.getQueryString();
        if (reqQueryString != null) {
            queryString = removeIgnoredHeaderNamesPattern.matcher(reqQueryString).replaceAll("");
        }
    }

    private void parsePathInfo(String pathInfo) {
        Matcher matcher = pathInfoPattern.matcher(pathInfo);

        if (matcher.matches()) {

            userName = matcher.group("username");
            password = matcher.group("password");

            scheme = matcher.group("scheme");
            if (scheme == null) {
                scheme = DEFAULT_SCHEME;
            }

            host = matcher.group("host");

            if (matcher.group("port") != null) {
                port = Integer.parseInt(matcher.group("port"));
            } else {
                port = (scheme.equalsIgnoreCase(DEFAULT_SCHEME)) ? DEFAULT_PORT : HTTPS_PORT;
            }

            path = matcher.group("path");
            if (!path.startsWith("/")) {
                path = "/" + path;
            }

            // replace invalid quotes " in path (as remote jolokia is using this proxy which may include " in the uri which the URI parser would fail)
            if (path.contains("\"")) {
                path = path.replaceAll("\\\"", "%22");
            }

            // we do not support query parameters

            if (LOG.isDebugEnabled()) {
                LOG.debug("Proxying to " + getStringProxyURL() + " as user: " + userName);
            }
        }
    }

    @Override
    public String toString() {
        return "ProxyDetails{" +
                userName + "@" + getStringProxyURL()
                + "}";
    }

    public String getStringProxyURL() {
        return scheme + "://" + getHostAndPort() + path + (Strings.isBlank(queryString) ? "" : "?" + queryString) ;
    }

    public String getProxyPath() {
        return path;
    }

    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public String getHostAndPort() {
        if (scheme.equalsIgnoreCase(DEFAULT_SCHEME) && port == DEFAULT_PORT) {
            return host;
        }
        if (scheme.equalsIgnoreCase(HTTPS_SCHEME) && port == HTTPS_PORT) {
            return host;
        }
        return host + ":" + port;
    }

    public int getPort() {
        return port;
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public String getPath() {
        return path;
    }

    public boolean isValid() {
        return host != null;
    }
}
