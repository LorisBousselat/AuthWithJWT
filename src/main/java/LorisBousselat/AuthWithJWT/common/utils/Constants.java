package LorisBousselat.AuthWithJWT.common.utils;

import com.auth0.jwt.algorithms.Algorithm;

public class Constants {
    public final static Algorithm ALGORITHM = Algorithm.HMAC256("Oq7sTH3vro1OqoWwHDFqVVAmNT3NZK8GSyIHocheiYTRPnYQYbRtQZxGiMwIlEAvinWkLKeWuNYGlxQlvyd5lJGgNxQmtNwTBciCdMR24SyUFSD7hp3OQh0hkumyCIoE0EQ1LqxL9Rlnq3hJpLqTEFWfBixtPIjJ9aTI");
    public static final String BEARER_ = "Bearer ";
    public static final String ROLES = "roles";
}
