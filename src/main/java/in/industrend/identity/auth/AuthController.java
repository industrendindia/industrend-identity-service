package in.industrend.identity.auth;

import in.industrend.identity.web.RequestSecurity;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
  record OtpRequest(@NotBlank String mobile,String purpose) {}
  record VerifyRequest(UUID challengeId,@Pattern(regexp="[0-9]{6}") String otp) {}
  record PinLoginRequest(@NotBlank String mobile,@Pattern(regexp="[0-9]{6}") String pin) {}
  record PinSetRequest(@Pattern(regexp="[0-9]{6}") String pin) {}

  private final AuthService auth;
  private final RequestSecurity security;
  private final boolean secure;

  AuthController(AuthService auth,RequestSecurity security,@Value("${app.security.cookie-secure:true}") boolean secure) {
    this.auth=auth; this.security=security; this.secure=secure;
  }

  @PostMapping("/otp/request")
  public AuthService.Challenge request(@Valid @RequestBody OtpRequest body,HttpServletRequest request) {
    if(body.purpose()!=null&&!"LOGIN".equalsIgnoreCase(body.purpose())&&!"PIN_RESET".equalsIgnoreCase(body.purpose())) {
      security.requireCustomer(request); security.requireCsrf(request);
    }
    return auth.requestOtp(body.mobile(),body.purpose(),clientIp(request));
  }

  @PostMapping("/otp/verify")
  public AuthService.AuthResult verify(@Valid @RequestBody VerifyRequest body,HttpServletRequest request,HttpServletResponse response) {
    var result=auth.verify(body.challengeId(),body.otp(),clientIp(request),request.getHeader("User-Agent"),(UUID)request.getAttribute("customerId"));
    setCookie(response,result.sessionToken(),result.expiresInSeconds()); return result;
  }

  @PostMapping("/pin/login")
  public AuthService.AuthResult pinLogin(@Valid @RequestBody PinLoginRequest body,HttpServletRequest request,HttpServletResponse response) {
    var result=auth.loginWithPin(body.mobile(),body.pin(),clientIp(request),request.getHeader("User-Agent"));
    setCookie(response,result.sessionToken(),result.expiresInSeconds()); return result;
  }

  @PostMapping("/pin")
  public Map<String,Boolean> setPin(@Valid @RequestBody PinSetRequest body,HttpServletRequest request) {
    security.requireCsrf(request); auth.setPin(security.requireCustomer(request),body.pin()); return Map.of("pinConfigured",true);
  }

  @GetMapping("/session")
  public AuthService.AuthResult session(HttpServletRequest request) {
    return auth.current(security.requireCustomer(request),(UUID)request.getAttribute("sessionId"));
  }

  @PostMapping("/logout")
  public Map<String,Boolean> logout(HttpServletRequest request,HttpServletResponse response) {
    security.requireCustomer(request); security.requireCsrf(request); auth.logout((String)request.getAttribute("sessionToken")); setCookie(response,"",0); return Map.of("loggedOut",true);
  }

  private void setCookie(HttpServletResponse response,String value,long ttl) {
    response.addHeader("Set-Cookie",ResponseCookie.from(SessionFilter.COOKIE,value).httpOnly(true).secure(secure).sameSite("Lax").path("/").maxAge(Duration.ofSeconds(ttl)).build().toString());
  }
  private String clientIp(HttpServletRequest request) { var forwarded=request.getHeader("X-Forwarded-For"); return forwarded==null?request.getRemoteAddr():forwarded.split(",")[0].trim(); }
}
