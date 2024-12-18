// Needs to be a var at the top level to get hoisted to global scope.
// https://stackoverflow.com/questions/28776079/do-let-statements-create-properties-on-the-global-object/28776236#28776236
var aadOauth = (function () {
  let myMSALObj = null;
  let authResult = null;
  let redirectHandlerTask = null;

  const tokenRequest = {
    scopes: null,
    prompt: null,
    extraQueryParameters: {},
    loginHint: null
  };

  // Initialise the myMSALObj for the given client, authority and scope
 function init(config) {
     // TODO: Add support for other MSAL configuration
     var authData = {
         clientId: config.clientId,
         authority: config.isB2C ? "https://" + config.tenant + ".b2clogin.com/tfp/" + config.tenant + ".onmicrosoft.com/" + config.policy + "/" : "https://login.microsoftonline.com/" + config.tenant,
         knownAuthorities: [ config.tenant + ".b2clogin.com", "login.microsoftonline.com"],
         redirectUri: config.redirectUri,
     };
     var postLogoutRedirectUri = {
         postLogoutRedirectUri: config.postLogoutRedirectUri,
     };
     var msalConfig = {
         auth: config?.postLogoutRedirectUri == null ? {
             ...authData,
         } : {
             ...authData,
             ...postLogoutRedirectUri,
         },
         cache: {
             cacheLocation: config.cacheLocation,
             storeAuthStateInCookie: false,
         },
         system: config.enableLogging !==true?null: {
          loggerOptions: {
              loggerCallback(loglevel, message, containsPii) {
                  console.log(message);
              },
              piiLoggingEnabled: false,
              logLevel: msal.LogLevel.Verbose,
            }
          }
     };

     if (typeof config.scope === "string") {
         tokenRequest.scopes = config.scope.split(" ");
     } else {
         tokenRequest.scopes = config.scope;
     }

     tokenRequest.extraQueryParameters = JSON.parse(config.customParameters);
     tokenRequest.prompt = config.prompt;
     tokenRequest.loginHint = config.loginHint;

     myMSALObj = new msal.PublicClientApplication(msalConfig);
     // Register Callbacks for Redirect flow and record the task so we
     // can await its completion in the login API

     redirectHandlerTask = myMSALObj.handleRedirectPromise();
 }

  // Tries to silently acquire a token. Will return null if a token
  // could not be acquired or if no cached account credentials exist.
  // Will return the authentication result on success and update the
  // global authResult variable.
  async function silentlyAcquireToken() {
    try {
      
      // The redirect handler task will complete with auth results if we
      // were redirected from AAD. If not, it will complete with null
      // We must wait for it to complete before we allow the login to
      // attempt to acquire a token silently, and then progress to interactive
      // login (if silent acquisition fails).
      let result = await redirectHandlerTask;

      if (result !== null) {
        authResult = result;
        return authResult;
      }
    }
    catch (error) {
      authResultError = null;
    }

    const account = getAccount();
    if (account == null) {
      return null;
    }
    try {
      // Silent acquisition only works if the access token is either
      // within its lifetime, or the refresh token can successfully be
      // used to refresh it. This will throw if the access token can't
      // be acquired.
      const silentAuthResult = await myMSALObj.acquireTokenSilent({
        scopes: tokenRequest.scopes,
        prompt: "none",
        account: account,
        extraQueryParameters: tokenRequest.extraQueryParameters
      });
      return  authResult = silentAuthResult;
    } catch (error) {
      console.log('Unable to silently acquire a new token: ' + error.message)
      return null;
    }

  }

  /// Authorize user via refresh token or web gui if necessary.
  ///
  /// Setting [refreshIfAvailable] to [true] should attempt to re-authenticate
  /// with the existing refresh token, if any, even though the access token may
  /// still be valid; however MSAL doesn't support this. Therefore it will have
  /// the same impact as when it is set to [false].
  /// [useRedirect] uses the MSAL redirection based token acquisition instead of
  /// a popup window. This is the only way that iOS based devices will acquire
  /// a token using MSAL when the application is installed to the home screen.
  /// This is because the popup window operates outside the sandbox of the PWA and
  /// won't share cookies or local storage with the PWA sandbox. Redirect flow works
  /// around this issue by having the MSAL authentication take place directly within
  /// the PWA sandbox browser.
  /// The token is requested using acquireTokenSilent, which will refresh the token
  /// if it has nearly expired. If this fails for any reason, it will then move on
  /// to attempt to refresh the token using an interactive login.

  async function login(refreshIfAvailable, useRedirect, onSuccess, onError) {

    // Try to sign in silently, assuming we have already signed in and have
    // a cached access token
    await silentlyAcquireToken()
    if(authResult != null) {
      // Skip interactive login
      onSuccess(authResult ? JSON.stringify(authResult) : null);
      return
    }

    const account = getAccount()
    if (useRedirect) {

      myMSALObj.acquireTokenRedirect({
        scopes: tokenRequest.scopes,
        prompt: tokenRequest.prompt,
        account: account,
        extraQueryParameters: tokenRequest.extraQueryParameters,
        loginHint: tokenRequest.loginHint
      });
    } else {
      // Sign in with popup
      try {
        const interactiveAuthResult = await myMSALObj.loginPopup({
          scopes: tokenRequest.scopes,
          prompt: tokenRequest.prompt,
          account: account,
          extraQueryParameters: tokenRequest.extraQueryParameters,
          loginHint: tokenRequest.loginHint
        });

        authResult = interactiveAuthResult;

        onSuccess(authResult ? JSON.stringify(authResult) : null);
      } catch (error) {
        // rethrow
        console.warn(error.message);
        onError(error);
      }
    }
  }

  // Tries to refresh the token. Will call [onError] if a token
  // could not be acquired or if no cached account credentials exist.
  // Will call [onSuccess] on success and update the global authResult variable.
  async function refreshToken(onSuccess, onError) {
    try {
      // The redirect handler task will complete with auth results if we
      // were redirected from AAD. If not, it will complete with null
      // We must wait for it to complete before we allow the login to
      // attempt to acquire a token silently, and then progress to interactive
      // login (if silent acquisition fails).
      let result = await redirectHandlerTask;
      if (result !== null) {
        authResult = result;
      }
    }
    catch (error) {
      authResultError = error;
      onError(authResultError);
      return;
    }

    // Try to sign in silently, assuming we have already signed in and have
    // a cached access token
    await silentlyAcquireToken()

    if(authResult != null) {
      onSuccess(authResult ? JSON.stringify(authResult) : null);
      return
    }
  }

  function getAccount() {
    // If we have recently authenticated, we use the auth'd account;
    // otherwise we fallback to using MSAL APIs to find cached auth
    // accounts in browser storage.
    if (authResult !== null && authResult.account !== null) {
      return authResult.account
    }

    const currentAccounts = myMSALObj.getAllAccounts();

    if (currentAccounts === null || currentAccounts.length === 0) {
      return null;
    } else if (currentAccounts.length > 1) {
      // Multiple users - pick the first one, but this shouldn't happen
      console.warn("Multiple accounts detected, selecting first.");

      return currentAccounts[0];
    } else if (currentAccounts.length === 1) {
      return currentAccounts[0];
    }
  }

  
  function clearCookies() {
    const cookies = document.cookie.split(";");

    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i];
      const eqPos = cookie.indexOf("=");
      const name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
      document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
    }
  }  
  
  async function clearCacheAndCookies() {
    // Limpar localStorage e sessionStorage
    localStorage.clear();
    sessionStorage.clear();
    clearCookies();
    await myMSALObj.clearCache();

  }
  function logout(onSuccess, onError, showPopup) {
    const account = getAccount();

    if (!account) {
      clearCacheAndCookies();
      onSuccess();
      return;
    }
    authResult = null;

    if (showPopup) {
      myMSALObj
        .logout({ account: account })
        .then((_) => {
          clearCacheAndCookies();
          onSuccess();
        })
        .catch(onError);
    } else {

   
      myMSALObj
        .logoutRedirect({
          account: account,
          onRedirectNavigate: (url) => {
            return false;
          }
        })
        .then((_) => {
          clearCacheAndCookies();
          onSuccess();
        })
        .catch(onError);
     
    }


  }

  async function getAccessToken() {
    var result = await silentlyAcquireToken()
    return result ? result.accessToken : null;
  }

  async function getIdToken() {
    var result = await silentlyAcquireToken()
    return result ? result.idToken : null;
  }
  async function getToken() {
    var result = await silentlyAcquireToken()
    return result ? JSON.stringify(result) : null;
  }

  function hasCachedAccountInformation() {
    return getAccount() != null;
  }

  return {
    init: init,
    login: login,
    refreshToken: refreshToken,
    logout: logout,
    getIdToken: getIdToken,
    getAccessToken: getAccessToken,
    hasCachedAccountInformation: hasCachedAccountInformation,
    getToken: getToken,
  };
})();
