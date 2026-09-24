package in.industrend.identity.web;
import in.industrend.identity.auth.SecurityTokens;import jakarta.servlet.http.HttpServletRequest;import java.util.UUID;import org.springframework.stereotype.Component;
@Component
public class RequestSecurity {
  private final SecurityTokens tokens; public RequestSecurity(SecurityTokens tokens){this.tokens=tokens;}
  public UUID requireCustomer(HttpServletRequest req){var id=(UUID)req.getAttribute("customerId");if(id==null)throw new Unauthorized("Authentication required");return id;}
  public void requireCsrf(HttpServletRequest req){var expected=(String)req.getAttribute("csrfHash");var actual=req.getHeader("X-CSRF-Token");if(expected==null||actual==null||!tokens.matches(expected,actual))throw new Unauthorized("Invalid security token");}
  public static class Unauthorized extends RuntimeException{public Unauthorized(String message){super(message);}}
}