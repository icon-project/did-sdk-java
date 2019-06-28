package foundation.icon.did.api;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class CredentialResponse extends ApiResponse {
    String credentialClaim;
}
