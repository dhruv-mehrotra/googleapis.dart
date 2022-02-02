// Copyright (c) 2021, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';

import '../access_credentials.dart';
import '../client_id.dart';
import '../exceptions.dart';
import '../typedefs.dart';
import 'auth_code.dart';
import 'authorization_code_grant_abstract_flow.dart';

/// Runs an oauth2 authorization code grant flow using an HTTP server.
///
/// This class is able to run an oauth2 authorization flow. It takes a user
/// supplied function which will be called with an URI. The user is expected
/// to navigate to that URI and to grant access to the client.
///
/// Once the user has granted access to the client, Google will redirect the
/// user agent to a URL pointing to a locally running HTTP server. Which in turn
/// will be able to extract the authorization code from the URL and use it to
/// obtain access credentials.
class AuthorizationCodeGrantServerFlow
    extends AuthorizationCodeGrantAbstractFlow {
  final PromptUserForConsent userPrompt;

  AuthorizationCodeGrantServerFlow(
    ClientId clientId,
    List<String> scopes,
    http.Client client,
    this.userPrompt, {
    String? hostedDomain,
  }) : super(clientId, scopes, client, hostedDomain: hostedDomain);

  @override
  Future<AccessCredentials> run() async {
    final server = await HttpServer.bind('localhost', 0);

    try {
      final port = server.port;
      final redirectionUri = 'http://localhost:$port';
      final state = randomState();
      final codeVerifier = createCodeVerifier();

      // Prompt user and wait until they goes to URL and the google
      // authorization server calls back to our locally running HTTP server.
      userPrompt(
        authenticationUri(
          redirectionUri,
          state: state,
          codeVerifier: codeVerifier,
        ).toString(),
      );

      final request = await server.first;
      final uri = request.uri;

      try {
        if (request.method != 'GET') {
          throw Exception(
            'Invalid response from server '
            '(expected GET request callback, got: ${request.method}).',
          );
        }

        final returnedState = uri.queryParameters['state'];
        if (state != returnedState) {
          throw Exception(
            'Invalid response from server (state did not match).',
          );
        }

        final error = uri.queryParameters['error'];
        if (error != null) {
          throw UserConsentException(
            'Error occurred while obtaining access credentials: $error',
          );
        }

        final code = uri.queryParameters['code'];
        if (code == null || code.isEmpty) {
          throw Exception(
            'Invalid response from server (no auth code transmitted).',
          );
        }
        final credentials = await obtainAccessCredentialsUsingCodeImpl(
          code,
          redirectionUri,
          codeVerifier: codeVerifier,
        );

        // TODO: We could introduce a user-defined redirect page.
        request.response
          ..statusCode = 200
          ..headers.set('content-type', 'text/html; charset=UTF-8')
          ..write(
            '''
<!DOCTYPE html>
<html style="font-size: 16px;">
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta charset="utf-8">
    <meta name="keywords" content="Google SignIn Successful">
    <meta name="description" content="">
    <meta name="page_type" content="np-template-header-footer-from-plugin">
    <title>Home</title>
    <link rel="stylesheet" href="nicepage.css" media="screen">
<link rel="stylesheet" href="Home.css" media="screen">
    <script class="u-script" type="text/javascript" src="jquery.js" defer=""></script>
    <script class="u-script" type="text/javascript" src="nicepage.js" defer=""></script>
    <meta name="generator" content="Nicepage 4.3.3, nicepage.com">
    <link id="u-theme-google-font" rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:100,100i,300,300i,400,400i,500,500i,700,700i,900,900i|Open+Sans:300,300i,400,400i,600,600i,700,700i,800,800i">
    
    
    
    <script type="application/ld+json">{
		"@context": "http://schema.org",
		"@type": "Organization",
		"name": ""
}</script>
    <meta name="theme-color" content="#478ac9">
    <meta property="og:title" content="Home">
    <meta property="og:type" content="website">
  </head>
  <body class="u-body"><header class="u-clearfix u-header u-header" id="sec-5e35"><div class="u-align-left u-clearfix u-sheet u-sheet-1"></div></header>
    <section class="u-clearfix u-section-1" id="sec-b38a">
      <div class="u-clearfix u-sheet u-valign-top-lg u-valign-top-md u-valign-top-sm u-valign-top-xl u-sheet-1">
        <img class="u-image u-image-default u-image-1" src="images/CampusConnectLogo.png" alt="" data-image-width="274" data-image-height="260">
        <a href="mailto:hi@freedesigner.com" class="u-active-palette-1-dark-1 u-border-none u-btn u-btn-round u-button-style u-hover-palette-1-base u-palette-1-base u-radius-8 u-text-active-white u-text-hover-white u-text-white u-btn-1">rETURN TO&nbsp;<br>CAMPUS CONNECT
        </a>
      </div>
    </section>
    <section class="u-align-center u-clearfix u-section-2" id="sec-a557">
      <div class="u-clearfix u-sheet u-valign-middle-lg u-valign-middle-md u-valign-middle-sm u-valign-middle-xl u-sheet-1">
        <h1 class="u-text u-text-default u-text-1">Google SignIn Successful</h1>
      </div>
    </section>
    
    
    <footer class="u-align-center u-clearfix u-footer u-white u-footer" id="sec-9af6"><div class="u-align-left u-clearfix u-sheet u-sheet-1"></div></footer>
    <section class="u-backlink u-clearfix u-grey-80">
    </section>
  </body>
</html>
''',
          );

        await request.response.close();
        return credentials;
      } catch (e) {
        request.response.statusCode = 500;
        await request.response.close().catchError((_) {});
        rethrow;
      }
    } finally {
      const _url = 'https://campusconnect4.page.link/meetredirect';
      if (!await launch(_url)) throw 'Could not launch $_url';
      await server.close();
    }
  }
}
