package provider;

import com.dev.security.model.JWTValidationToken;
import com.dev.security.util.JWTUtil;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;


public class JWTValidationProvider implements AuthenticationProvider {

    private final JWTUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public JWTValidationProvider(JWTUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        JWTValidationToken authObj = (JWTValidationToken) authentication;
        String jwtToken = authObj.getToken();
        String email = jwtUtil.extractEmail(jwtToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        if (userDetails != null && jwtUtil.validateToken(jwtToken, userDetails))
        {
            return new JWTValidationToken(userDetails, userDetails.getAuthorities());
        }

        throw new BadCredentialsException("Invalid Token");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JWTValidationToken.class.isAssignableFrom(authentication);
    }
}
