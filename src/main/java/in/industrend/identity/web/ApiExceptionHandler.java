package in.industrend.identity.web;
import java.util.Map;import org.springframework.http.HttpStatus;import org.springframework.http.ResponseEntity;import org.springframework.http.converter.HttpMessageNotReadableException;import org.springframework.web.bind.MethodArgumentNotValidException;import org.springframework.web.bind.annotation.ExceptionHandler;import org.springframework.web.bind.annotation.RestControllerAdvice;
@RestControllerAdvice
public class ApiExceptionHandler {
  @ExceptionHandler(RequestSecurity.Unauthorized.class) ResponseEntity<?> unauthorized(RuntimeException e){return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error",e.getMessage()));}
  @ExceptionHandler({IllegalArgumentException.class,MethodArgumentNotValidException.class,HttpMessageNotReadableException.class}) ResponseEntity<?> badRequest(Exception e){return ResponseEntity.badRequest().body(Map.of("error",e instanceof MethodArgumentNotValidException?"Check the submitted details":e.getMessage()));}
  @ExceptionHandler(Exception.class) ResponseEntity<?> server(Exception e){return ResponseEntity.status(500).body(Map.of("error","The request could not be completed"));}
}