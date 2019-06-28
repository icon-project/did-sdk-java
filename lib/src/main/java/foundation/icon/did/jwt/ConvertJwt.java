package foundation.icon.did.jwt;

import foundation.icon.did.Credential;
import foundation.icon.did.Presentation;

import java.util.Date;

/**
 * A interface to convert {@linkplain Credential} and {@linkplain Presentation} to 'Json Web Token'
 */
public interface ConvertJwt {

    /**
     * The time in seconds from the issued time to expiration
     *
     * @return the duration in seconds
     */
    int getDuration();

    /**
     * Create a new JWT with default iat and exp
     * <p>
     * default iat : the current time
     * default exp : default iat + {@code getDuration()}
     *
     * @return the Jwt object
     */
    default Jwt buildJwt() {
        Date issued = new Date();
        long duration = getDuration() * 1000L;  // to milliseconds
        Date expiration = new Date(issued.getTime() + duration);
        return buildJwt(issued, expiration);
    }

    /**
     * Create a new JWT
     *
     * @param issued     the time at which the JWT was issued
     * @param expiration the time at which the JWT must not be accepted for processing
     * @return the JWT object
     */
    Jwt buildJwt(Date issued, Date expiration);


}
