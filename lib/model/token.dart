/// Access token enabling to securely call protected APIs on behalf of the user.
class Token {
  /// Offset which is subtracted from expire time
  final expireOffSet = 5;

  /// The requested access token. The app can use this token to authenticate to the secured resource, such as a web API.
  String? accessToken;

  /// Indicates the token type value. The only type that Azure AD supports is Bearer.
  String? tokenType;

  /// An OAuth 2.0 refresh token. The app can use this token acquire additional access tokens after the current access token expires. Refresh_tokens are long-lived, and can be used to retain access to resources for extended periods of time. For more detail on refreshing an access token, refer to the section below.
  /// Note: Only provided if offline_access `scope` was requested.
  String? refreshToken;

  /// A JSON Web Token (JWT). The app can decode the segments of this token to request information about the user who signed in.
  /// The app can cache the values and display them, and confidential clients can use this for authorization.
  /// For more information about id_tokens, see the id_token reference.
  /// Note: Only provided if openid `scope` was requested.
  String? idToken;

  /// Current time when token was issued.
  late DateTime issueTimeStamp;

  /// Predicted token expiration time.
  DateTime? expireTimeStamp;

  /// How long the access token is valid (in seconds).
  int? expiresIn;

  /// The time when the token expires.
  DateTime? expiresOn;
  DateTime? extExpiresOn;

  ///
  /// Indicates whether the token was retrieved from the cache.
  ///
  /// If `true`, the token was loaded from the cache. If `false` or `null`,
  /// the token was obtained through a new authentication request.
  bool? fromCache;

  /// Access token enabling to securely call protected APIs on behalf of the user.
  Token({this.accessToken});

  /// JSON map to Token factory.
  factory Token.fromJson(Map<String, dynamic>? json) => Token.fromMap(json);

  /// Convert this Token to JSON map.
  Map toMap() => Token.toJsonMap(this);

  @override
  String toString() => Token.toJsonMap(this).toString();

  /// Convert Token to JSON map.
  static Map toJsonMap(Token model) {
    var ret = {};
    if (model.accessToken != null) {
      ret['accessToken'] = model.accessToken;
    }
    if (model.tokenType != null) {
      ret['tokenType'] = model.tokenType;
    }
    if (model.refreshToken != null) {
      ret['refresh_token'] = model.refreshToken;
    }
    if (model.expiresIn != null) {
      ret['expires_in'] = model.expiresIn;
    }
    if (model.expireTimeStamp != null) {
      ret['expire_timestamp'] = model.expireTimeStamp!.millisecondsSinceEpoch;
    }
    if (model.idToken != null) {
      ret['idToken'] = model.idToken;
    }
    if (model.expiresOn != null) {
      ret['expiresOn'] = model.expiresOn!.toIso8601String();
    }
    if (model.extExpiresOn != null) {
      ret['extExpiresOn'] = model.extExpiresOn!.toIso8601String();
    }
    if (model.fromCache != null) {
      ret['fromCache'] = model.fromCache;
    }
    return ret;
  }

  /// Convert JSON map to Token.
  static Token fromMap(Map<String, dynamic>? map) {
    if (map == null) throw Exception('No token from received');
    //error handling as described in https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#error-response-1
    if (map['error'] != null) {
      throw Exception(
          'Error during token request: ${map['error']}: ${map['error_description']}');
    }

    var model = Token();
    model.accessToken = map['accessToken'];
    model.tokenType = map['tokenType'];
    model.expiresIn = map['expires_in'] is int
        ? map['expires_in']
        : int.tryParse(map['expires_in'].toString()) ?? 60;
    model.expiresOn =
        map['expiresOn'] != null ? DateTime.parse(map['expiresOn']) : null;
    model.extExpiresOn = map['extExpiresOn'] != null
        ? DateTime.parse(map['extExpiresOn'])
        : null;
    model.refreshToken = map['refresh_token'];
    model.idToken = map.containsKey('idToken') ? map['idToken'] : '';
    model.issueTimeStamp = DateTime.now().toUtc();
    model.expireTimeStamp = map.containsKey('expire_timestamp')
        ? DateTime.fromMillisecondsSinceEpoch(map['expire_timestamp'])
        : model.issueTimeStamp
            .add(Duration(seconds: model.expiresIn! - model.expireOffSet));
    model.fromCache = map.containsKey('fromCache') ? map['fromCache'] : '';
    return model;
  }

  /// Check if Access Token is set and not expired.
  bool hasValidAccessToken() {
    return accessToken != null &&
        expireTimeStamp != null &&
        expireTimeStamp!.isAfter(DateTime.now().toUtc());
  }

  /// Check if Refresh Token is set.
  bool hasRefreshToken() {
    return refreshToken != null;
  }
}
