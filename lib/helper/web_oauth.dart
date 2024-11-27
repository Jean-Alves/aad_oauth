/// Microsoft identity platform authentication library.
/// @nodoc
@JS('aadOauth')
library msauth;

import 'dart:async';
import 'dart:convert';

import 'package:aad_oauth/helper/core_oauth.dart';
import 'package:aad_oauth/model/config.dart';
import 'package:aad_oauth/model/failure.dart';
import 'package:aad_oauth/model/msalconfig.dart';
import 'package:aad_oauth/model/token.dart';
import 'package:dartz/dartz.dart';
import 'package:js/js.dart';
import 'package:js/js_util.dart';

@JS('init')
external void jsInit(MsalConfig config);

@JS('login')
external void jsLogin(
  bool refreshIfAvailable,
  bool useRedirect,
  void Function(dynamic) onSuccess,
  void Function(dynamic) onError,
);

@JS('logout')
external void jsLogout(
  void Function() onSuccess,
  void Function(dynamic) onError,
  bool showPopup,
);

@JS('getAccessToken')
external Object jsGetAccessToken();

@JS('getIdToken')
external Object jsGetIdToken();

@JS('getToken')
external Object jsGetToken();

@JS('hasCachedAccountInformation')
external bool jsHasCachedAccountInformation();

@JS('refreshToken')
external void jsRefreshToken(
  void Function(dynamic) onSuccess,
  void Function(dynamic) onError,
);

class WebOAuth extends CoreOAuth {
  final Config config;
  WebOAuth(this.config) {
    jsInit(MsalConfig.construct(
      tenant: config.tenant,
      policy: config.policy,
      clientId: config.clientId,
      responseType: config.responseType,
      redirectUri: config.redirectUri,
      scope: config.scope,
      responseMode: config.responseMode,
      state: config.state,
      prompt: config.prompt,
      codeChallenge: config.codeChallenge,
      codeChallengeMethod: config.codeChallengeMethod,
      nonce: config.nonce,
      tokenIdentifier: config.tokenIdentifier,
      clientSecret: config.clientSecret,
      resource: config.resource,
      isB2C: config.isB2C,
      customAuthorizationUrl: config.customAuthorizationUrl,
      customTokenUrl: config.customTokenUrl,
      loginHint: config.loginHint,
      domainHint: config.domainHint,
      codeVerifier: config.codeVerifier,
      authorizationUrl: config.authorizationUrl,
      tokenUrl: config.tokenUrl,
      cacheLocation: config.cacheLocation.value,
      customParameters: jsonEncode(config.customParameters),
      postLogoutRedirectUri: config.postLogoutRedirectUri,
      enableLogging: config.enableLogging,
    ));
  }

  @override
  Future<String?> getAccessToken() async {
    return promiseToFuture(jsGetAccessToken());
  }

  @override
  Future<String?> getIdToken() async {
    return promiseToFuture(jsGetIdToken());
  }

  @override
  Future<Token?> getToken() async {
    final token = await promiseToFuture(jsGetToken());
    if (token == null) return null;
    final decodedValue = json.decode(token) as Map<String, dynamic>;
    return Token.fromJson(decodedValue);
  }

  @override
  Future<bool> get hasCachedAccountInformation =>
      Future<bool>.value(jsHasCachedAccountInformation());

  @override
  Future<Either<Failure, Token>> login(
      {bool refreshIfAvailable = false}) async {
    final completer = Completer<Either<Failure, Token>>();

    jsLogin(
      refreshIfAvailable,
      config.webUseRedirect,
      allowInterop(
        (value) {
          try {
            final decodedValue = json.decode(value) as Map<String, dynamic>;

            completer.complete(Right(Token.fromJson(decodedValue)));
          } catch (error) {
            completer.complete(
              Left(
                AadOauthFailure(
                  errorType: ErrorType.invalidJson,
                  message:
                      'Error: Failed to convert token. Please verify the response structure or the provided data. Details: $error',
                ),
              ),
            );
          }
        },
      ),
      allowInterop(
        (error) => completer.complete(
          Left(
            AadOauthFailure(
              errorType: ErrorType.accessDeniedOrAuthenticationCanceled,
              message:
                  'Access denied or authentication canceled. Error: ${error.toString()}',
            ),
          ),
        ),
      ),
    );

    return completer.future;
  }

  @override
  Future<Either<Failure, Token>> refreshToken() {
    final completer = Completer<Either<Failure, Token>>();

    jsRefreshToken(
      allowInterop(
          (value) => completer.complete(Right(Token(accessToken: value)))),
      allowInterop((error) => completer.complete(Left(AadOauthFailure(
            errorType: ErrorType.accessDeniedOrAuthenticationCanceled,
            message:
                'Access denied or authentication canceled. Error: ${error.toString()}',
          )))),
    );

    return completer.future;
  }

  @override
  Future<Either<Failure, bool>> logout(
      {bool showPopup = true, bool clearCookies = true}) async {
    final completer = Completer<Either<Failure, bool>>();

    jsLogout(
      allowInterop(() => completer.complete(Right(true))),
      allowInterop(
        (error) => completer.complete(
          Left(
            AadOauthFailure(
              errorType: ErrorType.unexpectedError,
              message: 'Error during logout. Error: ${error.toString()}',
            ),
          ),
        ),
      ),
      showPopup,
    );

    return completer.future;
  }
}

CoreOAuth getOAuthConfig(Config config) => WebOAuth(config);
