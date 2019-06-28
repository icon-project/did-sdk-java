package foundation.icon.did.api;

import com.google.gson.Gson;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.http.Body;
import retrofit2.http.POST;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ClaimIssueApi {

    private Api api;

    public ClaimIssueApi(Retrofit retrofit) {
        this.api = retrofit.create(Api.class);
    }

    public AuthResponse checkOwner(String authType, String value, String didToken) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("type", authType);
        params.put("value", value);
        params.put("token", didToken);
        Response<AuthResponse> response = api.checkOwner(params).execute();
        if (response.isSuccessful())
            return response.body();
        else {
            return new Gson().fromJson(response.errorBody().charStream(), AuthResponse.class);
        }
    }

    public CredentialResponse sendCredentialClaim(String authNum, String didToken) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("authNum", authNum);
        params.put("authToken", didToken);
        Response<CredentialResponse> response = api.sendCredentialClaim(params).execute();
        if (response.isSuccessful())
            return response.body();
        else {
            return new Gson().fromJson(response.errorBody().charStream(), CredentialResponse.class);
        }
    }

    interface Api {
        @POST("/v1/issuer/checkOwner")
        Call<AuthResponse> checkOwner(@Body Map<String, String> params);

        @POST("/v1/issuer/sendCredentialClaim")
        Call<CredentialResponse> sendCredentialClaim(@Body Map<String, String> params);
    }
}
