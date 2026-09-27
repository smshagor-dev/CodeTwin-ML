use security_analyzer::analyze_source;

fn rules(source: &str) -> Vec<String> {
    let result = analyze_source("Java", source).expect("analyze");
    assert!(!result.parsed_with_errors, "fixture must parse:\n{source}");
    result
        .observations
        .into_iter()
        .map(|item| item.rule_id)
        .collect()
}

fn class(body: &str) -> String {
    format!("class T {{\n{body}\n}}\n")
}

#[test]
fn sql_built_from_strings() {
    let concatenated = class(
        r#"void f(java.sql.Statement stmt, String name) throws Exception {
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
}"#,
    );
    assert_eq!(rules(&concatenated), vec!["java.sql.concatenated_query"]);

    let request = class(
        r#"void f(java.sql.Statement stmt, javax.servlet.http.HttpServletRequest request) throws Exception {
    stmt.executeQuery("SELECT * FROM users WHERE id = " + request.getParameter("id"));
}"#,
    );
    assert_eq!(rules(&request), vec!["web.sql.request_to_query"]);

    let formatted = class(
        r#"void f(org.springframework.jdbc.core.JdbcTemplate jdbc, String table) {
    jdbc.queryForList(String.format("select * from %s", table));
}"#,
    );
    assert_eq!(rules(&formatted), vec!["java.sql.concatenated_query"]);

    let jpa = class(
        r#"void f(javax.persistence.EntityManager em, String sort) {
    em.createQuery("from Order o order by " + sort);
}"#,
    );
    assert_eq!(rules(&jpa), vec!["java.sql.concatenated_query"]);

    // Parameterized, fully literal, or not SQL at all.
    let safe = class(
        r#"void f(java.sql.Connection c, java.util.List<String> list, String id, String a) throws Exception {
    java.sql.PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE id = ?");
    ps.setString(1, id);
    ps.executeQuery();
    c.createStatement().executeQuery("SELECT " + "1");
    list.update("prefix-" + a);
    cache.update(a + "-suffix");
}"#,
    );
    assert!(rules(&safe).is_empty(), "{:?}", rules(&safe));
}

#[test]
fn process_execution() {
    let built = class(
        r#"void f(String host) throws Exception {
    Runtime.getRuntime().exec("ping -c 1 " + host);
}"#,
    );
    let found = analyze_source("Java", &built).unwrap().observations;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].rule_id, "java.command.dynamic_exec");
    assert_eq!(found[0].severity, "high");

    let request = class(
        r#"void f(javax.servlet.http.HttpServletRequest request) throws Exception {
    new ProcessBuilder("convert", request.getParameter("file")).start();
}"#,
    );
    assert_eq!(rules(&request), vec!["web.command.request_to_process"]);

    let literal = class(
        r#"void f() throws Exception {
    Runtime.getRuntime().exec("uptime");
    new ProcessBuilder("git", "status").start();
}"#,
    );
    assert!(rules(&literal).is_empty());
}

#[test]
fn weak_crypto() {
    let source = class(
        r#"void f(byte[] data) throws Exception {
    java.security.MessageDigest.getInstance("MD5");
    MessageDigest.getInstance("SHA-1");
    MessageDigest.getInstance("SHA-256");
    DigestUtils.md5Hex(data);
    javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");
    Cipher.getInstance("AES/ECB/PKCS5Padding");
    Cipher.getInstance("AES");
    Cipher.getInstance("AES/GCM/NoPadding");
}"#,
    );
    let found = rules(&source);
    assert_eq!(
        found
            .iter()
            .filter(|rule| *rule == "security.weak_cryptographic_hash")
            .count(),
        3,
        "{found:?}"
    );
    assert_eq!(
        found
            .iter()
            .filter(|rule| *rule == "java.crypto.weak_cipher")
            .count(),
        3,
        "{found:?}"
    );
}

#[test]
fn deserialization_and_xxe() {
    let source = class(
        r#"Object f(java.io.InputStream in, String xml) throws Exception {
    new java.io.ObjectInputStream(in).readObject();
    new java.beans.XMLDecoder(in).readObject();
    DocumentBuilderFactory.newInstance().newDocumentBuilder();
    return new XStream().fromXML(xml);
}"#,
    );
    let found = rules(&source);
    assert_eq!(
        found
            .iter()
            .filter(|rule| *rule == "java.deserialization.untrusted_stream")
            .count(),
        3,
        "{found:?}"
    );
    assert!(found.contains(&"java.xml.xxe_unhardened_parser".to_string()));

    let hardened = class(
        r#"void f() throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
}"#,
    );
    assert!(rules(&hardened).is_empty());
}

#[test]
fn tls_and_spring_configuration() {
    let source = class(
        r#"void f(javax.net.ssl.HttpsURLConnection conn, HttpSecurity http) throws Exception {
    conn.setHostnameVerifier((hostname, session) -> true);
    HttpsURLConnection.setDefaultHostnameVerifier(NoopHostnameVerifier.INSTANCE);
    http.csrf().disable();
    http.csrf(AbstractHttpConfigurer::disable);
    http.csrf(csrf -> csrf.ignoringRequestMatchers("/webhook"));
}
public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
    // trust everyone
}
public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
}"#,
    );
    let found = rules(&source);
    assert_eq!(
        found
            .iter()
            .filter(|rule| *rule == "java.tls.hostname_verification_disabled")
            .count(),
        2,
        "{found:?}"
    );
    assert_eq!(
        found
            .iter()
            .filter(|rule| *rule == "java.spring.csrf_disabled")
            .count(),
        2,
        "{found:?}"
    );
    assert_eq!(
        found
            .iter()
            .filter(|rule| *rule == "java.tls.trust_all_certificates")
            .count(),
        1,
        "{found:?}"
    );

    let validating = class(
        r#"public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws Exception {
    delegate.checkServerTrusted(chain, authType);
}"#,
    );
    assert!(rules(&validating).is_empty());
}

#[test]
fn request_controlled_sinks() {
    let source = class(
        r#"void f(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, RestTemplate rest) throws Exception {
    response.sendRedirect(request.getParameter("next"));
    response.setHeader("X-Name", request.getHeader("X-Name"));
    rest.getForObject(request.getParameter("url"), String.class);
    new java.net.URL(request.getParameter("feed")).openStream();
    java.net.URL target = new java.net.URL(request.getParameter("hook"));
    target.openConnection();
    String host = new java.net.URL(request.getRequestURL().toString()).getHost();
    new java.io.File("/data/" + request.getParameter("name"));
    java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(request.getParameter("p")));
}"#,
    );
    let found = rules(&source);
    for rule in [
        "web.redirect.request_to_location",
        "web.header.request_to_response",
        "web.ssrf.request_url",
        "web.path.request_to_file",
    ] {
        assert!(found.contains(&rule.to_string()), "{rule}: {found:?}");
    }
    assert_eq!(
        found
            .iter()
            .filter(|rule| *rule == "web.ssrf.request_url")
            .count(),
        // getForObject, new URL(..).openStream() and target.openConnection(); the
        // new URL(..).getHost() parse is not a request.
        3,
        "{found:?}"
    );

    // The same APIs with fixed values are not reported.
    let fixed = class(
        r#"void f(javax.servlet.http.HttpServletResponse response, RestTemplate rest) throws Exception {
    response.sendRedirect("/login");
    rest.getForObject("https://api.example.com/status", String.class);
    new java.io.File("/data/report.csv");
}"#,
    );
    assert!(rules(&fixed).is_empty(), "{:?}", rules(&fixed));
}

#[test]
fn script_evaluation_and_credentials() {
    let source = class(
        r#"private static final String DB_PASSWORD = "Pr0d-S3cret!";
Object f(javax.script.ScriptEngine engine, String expr, ExpressionParser parser) throws Exception {
    parser.parseExpression(expr);
    engine.eval("1 + 1");
    return engine.eval(expr);
}"#,
    );
    let found = rules(&source);
    assert!(
        found.contains(&"security.hardcoded_credential_literal".to_string()),
        "{found:?}"
    );
    assert_eq!(
        found
            .iter()
            .filter(|rule| *rule == "security.dynamic_code_execution")
            .count(),
        2,
        "{found:?}"
    );
    let result = analyze_source("Java", &source).unwrap();
    assert!(result.observations.iter().any(|item| item.cwe == "CWE-917"));
}

#[test]
fn xss_respects_html_encoding_through_arrays_and_concatenation() {
    let vulnerable = class(
        r#"void f(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {
    String name = request.getParameter("name");
    Object[] args = {name, "x"};
    response.getWriter().printf("Hello %s %s", args);
}"#,
    );
    assert_eq!(rules(&vulnerable), vec!["web.xss.request_to_response"]);

    let encoded = class(
        r#"void f(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {
    String name = org.owasp.esapi.ESAPI.encoder().encodeForHTML(request.getParameter("name"));
    Object[] args = {name, "x"};
    response.getWriter().printf("Hello %s %s", args);
    response.getWriter().println("<b>" + name + "</b>");
    java.io.PrintWriter out = response.getWriter();
    out.write(org.springframework.web.util.HtmlUtils.htmlEscape(request.getParameter("q")));
}"#,
    );
    assert!(rules(&encoded).is_empty(), "{:?}", rules(&encoded));
}

#[test]
fn flow_sensitivity_and_constant_folding() {
    // Overwritten before the sink, dead branch, constant switch, list index and map key.
    let safe = class(
        r#"void f(javax.servlet.http.HttpServletRequest request, java.sql.Statement st) throws Exception {
    String param = request.getParameter("id");
    String a = param;
    a = "fixed";
    st.executeQuery("SELECT * FROM t WHERE a = '" + a + "'");

    int num = 86;
    String b;
    if ((7 * 42) - num > 200) b = "constant"; else b = param;
    st.executeQuery("SELECT * FROM t WHERE b = '" + b + "'");

    String guess = "ABC";
    String c;
    switch (guess.charAt(1)) {
        case 'A': c = param; break;
        case 'B': c = "bob"; break;
        default: c = param;
    }
    st.executeQuery("SELECT * FROM t WHERE c = '" + c + "'");

    java.util.List<String> list = new java.util.ArrayList<String>();
    list.add("safe");
    list.add(param);
    list.add("moresafe");
    list.remove(0);
    String d = list.get(1);
    st.executeQuery("SELECT * FROM t WHERE d = '" + d + "'");

    java.util.Map<String, Object> map = new java.util.HashMap<String, Object>();
    map.put("keyA", "a");
    map.put("keyB", param);
    String e = (String) map.get("keyA");
    st.executeQuery("SELECT * FROM t WHERE e = '" + e + "'");
}"#,
    );
    let found = rules(&safe);
    assert!(
        !found.contains(&"web.sql.request_to_query".to_string()),
        "{found:?}"
    );
    assert_eq!(
        found.len(),
        5,
        "each query is still a review-level concatenation: {found:?}"
    );

    // The same shapes with the tainted value reaching the sink.
    let vulnerable = class(
        r#"void f(javax.servlet.http.HttpServletRequest request, java.sql.Statement st, boolean flag) throws Exception {
    String param = request.getParameter("id");
    String b;
    if (flag) b = "constant"; else b = param;
    st.executeQuery("SELECT * FROM t WHERE b = '" + b + "'");
    java.util.List<String> list = new java.util.ArrayList<String>();
    list.add("safe");
    list.add(param);
    list.remove(0);
    String d = list.get(0);
    String sql = "SELECT * FROM t WHERE d = '" + d + "'";
    st.executeUpdate(sql);
    for (int i = 0; i < 2; i++) { sql = sql + param; }
}"#,
    );
    let found = rules(&vulnerable);
    assert_eq!(
        found
            .iter()
            .filter(|rule| *rule == "web.sql.request_to_query")
            .count(),
        2,
        "{found:?}"
    );
}

#[test]
fn spring_annotated_parameters_are_sources() {
    let source = r#"
@RestController
class Api {
    private final org.springframework.jdbc.core.JdbcTemplate jdbc;
    @GetMapping("/users")
    List<Map<String, Object>> users(@RequestParam String sort, String internal) {
        jdbc.queryForList("SELECT * FROM users ORDER BY " + internal);
        return jdbc.queryForList("SELECT * FROM users ORDER BY " + sort);
    }
    @GetMapping("/files/{name}")
    byte[] file(@PathVariable("name") String name) throws Exception {
        return java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/srv/files", name));
    }
}
"#;
    let found = rules(source);
    assert!(
        found.contains(&"web.sql.request_to_query".to_string()),
        "{found:?}"
    );
    assert!(
        found.contains(&"java.sql.concatenated_query".to_string()),
        "{found:?}"
    );
    assert!(
        found.contains(&"web.path.request_to_file".to_string()),
        "{found:?}"
    );
}

#[test]
fn same_file_helpers_are_summarised() {
    let source = r#"
class Handler {
    void doPost(javax.servlet.http.HttpServletRequest request, java.sql.Statement st) throws Exception {
        String param = request.getParameter("id");
        st.executeQuery("SELECT * FROM t WHERE a = '" + passThrough(param) + "'");
        st.executeQuery("SELECT * FROM t WHERE b = '" + constant(param) + "'");
    }
    private String passThrough(String value) { return value.trim(); }
    private String constant(String value) { return "fixed"; }
}
"#;
    let result = analyze_source("Java", source).unwrap();
    let confirmed: Vec<usize> = result
        .observations
        .iter()
        .filter(|item| item.rule_id == "web.sql.request_to_query")
        .map(|item| item.start_line)
        .collect();
    assert_eq!(confirmed, vec![5], "{:?}", result.observations);
}

#[test]
fn helpers_that_escape_html_are_safe_for_xss_only() {
    let source = r#"
class Page {
    void doGet(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, java.sql.Statement st) throws Exception {
        String name = escape(request.getParameter("name"));
        response.getWriter().print(name);
        st.executeQuery("SELECT * FROM t WHERE n = '" + name + "'");
        response.getWriter().print(raw(request.getParameter("raw")));
    }
    private static String escape(String value) { return org.springframework.web.util.HtmlUtils.htmlEscape(value); }
    private static String raw(String value) { return value; }
}
"#;
    let result = analyze_source("Java", source).unwrap();
    let found: Vec<(String, usize)> = result
        .observations
        .iter()
        .map(|item| (item.rule_id.clone(), item.start_line))
        .collect();
    // Escaped value: fine in HTML, still injectable into SQL. Unescaped helper: XSS.
    assert!(
        found.contains(&("web.sql.request_to_query".into(), 6)),
        "{found:?}"
    );
    assert!(
        found.contains(&("web.xss.request_to_response".into(), 7)),
        "{found:?}"
    );
    assert!(
        !found.contains(&("web.xss.request_to_response".into(), 5)),
        "{found:?}"
    );
}

#[test]
fn request_values_passed_into_same_file_helpers_are_tracked() {
    let source = r#"
@RestController
class Lesson {
    private final javax.sql.DataSource dataSource;
    private final RestTemplate rest;
    private String mailUrl;

    @PostMapping("/attack")
    String attack(@RequestParam String account, @RequestParam String email) {
        rest.postForEntity(mailUrl, email, Object.class);
        return injectable(account, "static");
    }

    private String injectable(String name, String fixed) throws Exception {
        java.sql.Statement st = dataSource.getConnection().createStatement();
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        st.executeQuery("SELECT * FROM users WHERE role = '" + fixed + "'");
        return "done";
    }
}
"#;
    let result = analyze_source("Java", source).unwrap();
    let found: Vec<(String, usize)> = result
        .observations
        .iter()
        .map(|item| (item.rule_id.clone(), item.start_line))
        .collect();
    assert!(
        found.contains(&("web.sql.request_to_query".into(), 16)),
        "{found:?}"
    );
    // The second parameter is only ever passed a constant.
    assert!(
        found.contains(&("java.sql.concatenated_query".into(), 17)),
        "{found:?}"
    );
    // A request-derived body sent to a configured URL is not SSRF.
    assert!(
        !found.iter().any(|(rule, _)| rule == "web.ssrf.request_url"),
        "{found:?}"
    );
}
