package in.industrend.identity.auth;
import jakarta.servlet.FilterChain;import jakarta.servlet.ServletException;import jakarta.servlet.http.Cookie;import jakarta.servlet.http.HttpServletRequest;import jakarta.servlet.http.HttpServletResponse;import java.io.IOException;import java.time.Instant;import java.util.Arrays;import java.util.UUID;import org.springframework.jdbc.core.simple.JdbcClient;import org.springframework.stereotype.Component;import org.springframework.web.filter.OncePerRequestFilter;
@Component
public class SessionFilter extends OncePerRequestFilter {
  public static final String COOKIE="IT_SESSION"; private final JdbcClient jdbc; private final SecurityTokens tokens;
  public SessionFilter(JdbcClient jdbc,SecurityTokens tokens){this.jdbc=jdbc;this.tokens=tokens;}
  protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
    res.setHeader("Cache-Control","no-store");res.setHeader("Pragma","no-cache");res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("X-Frame-Options","DENY");res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
    var token=Arrays.stream(req.getCookies()==null?new Cookie[0]:req.getCookies()).filter(c->COOKIE.equals(c.getName())).map(Cookie::getValue).findFirst().orElse(null);
    if(token!=null){jdbc.sql("select session_id,customer_id,csrf_hash,user_agent_hash from industrendindia.customer_sessions where token_hash=:h and revoked_at is null and expires_at>clock_timestamp()").param("h",tokens.hash(token)).query((rs,n)->{var userAgent=req.getHeader("User-Agent");if(rs.getString(4)!=null&&!tokens.matches(rs.getString(4),userAgent==null?"":userAgent))return 0;req.setAttribute("sessionId",rs.getObject(1,UUID.class));req.setAttribute("customerId",rs.getObject(2,UUID.class));req.setAttribute("csrfHash",rs.getString(3));req.setAttribute("sessionToken",token);return 1;}).optional();}
    chain.doFilter(req,res);
  }
}