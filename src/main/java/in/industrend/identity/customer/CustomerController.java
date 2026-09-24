package in.industrend.identity.customer;
import in.industrend.identity.web.RequestSecurity;import jakarta.servlet.http.HttpServletRequest;import java.util.Map;import java.util.UUID;import org.springframework.jdbc.core.simple.JdbcClient;import org.springframework.web.bind.annotation.*;
@RestController @RequestMapping("/api/v1")
public class CustomerController {
  record MobileChange(String mobile,UUID verificationChallengeId){}
  private final CustomerService customers;private final RequestSecurity security;private final JdbcClient jdbc;
  CustomerController(CustomerService customers,RequestSecurity security,JdbcClient jdbc){this.customers=customers;this.security=security;this.jdbc=jdbc;}
  @GetMapping("/customers/me") public CustomerService.Profile me(HttpServletRequest req){return customers.get(security.requireCustomer(req));}
  @PutMapping("/customers/me") public CustomerService.Profile save(@RequestBody CustomerService.ProfileInput body,HttpServletRequest req){security.requireCsrf(req);return customers.save(security.requireCustomer(req),body);}
  @PostMapping("/customers/me/mobile") public CustomerService.Profile mobile(@RequestBody MobileChange body,HttpServletRequest req){security.requireCsrf(req);return customers.changeMobile(security.requireCustomer(req),body.mobile(),body.verificationChallengeId());}
  @GetMapping("/locations/pincode/{pin}") public Map<String,String> pin(@PathVariable String pin){return jdbc.sql("select city,state_name from industrendindia.postal_code_reference where postal_code=:p and active").param("p",pin).query((r,n)->Map.of("city",r.getString(1),"state",r.getString(2))).optional().orElse(Map.of());}
}