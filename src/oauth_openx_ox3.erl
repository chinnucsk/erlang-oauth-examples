-module(oauth_openx_ox3).

-export([start/1, get_request_token/5, get_access_token/5, authorize_url/2, get_verifier/1,
        request_token_params/1, get_access_token/6]).

%% 
%% Useage:
%%
%% 1> Consumer = {"consume_key_given", "consumer_secret_given", hmac_sha1}.
%% 2> Domain = "sso_domain_given"
%% 3> Realm = "sso_realm_given"
%% 4> RequestTokenURL = "https://sso_domain_given/api/index/initiate".
%% 5> AccessTokenURL = "https://sso_domain_given/api/index/token".
%% 6> AuthorizeURL = "https://sso_domain_given/index/authorize".
%% 7> Callback = "callback_url"
%% 8> {ok, Client} = oauth_openx_ox3:start(Consumer).
%% 9> {ok, RToken} = oauth_openx_ox3:get_request_token(Client, RequestTokenURL, Callback, Realm, Domain).
%% 10> AuthorizationURL = oauth_openx_ox3:authorize_url(AuthorizeURL, RToken).
%% 11> Redirect to AuthorizationURL
%% -- Once the user is logged in, they will be redirected back to the router like this:
%%      callback?oauth_token=c554f48ea3e132112a61ae37e192a11604fc84e5d&oauth_verifier=544621ba94
%% 12> Uri = "callback_url_from_above"
%% 13> Verifier = oauth_openx_ox3:get_verifier(Uri)
%% 14> ok = oauth_openx_ox3:get_access_token(Client, AccessTokenURL, Verifier, Realm, Domain).
%% 15> AParams = oauth_client:access_token_params(Client).

start(Consumer) ->
  inets:start(),
  crypto:start(),
  ssl:start(),
  oauth_client:start(Consumer).

get_request_token(Client, URL, Callback, Realm, Domain) ->
  Args = [{"oauth_callback", Callback}],
  oauth_client:get_request_token(Client, URL, Args, header, Realm, Domain).

authorize_url(URL, Token) ->
  oauth:uri(URL, [{"oauth_token", Token}]).

get_access_token(Client, URL, Verifier, Realm, Domain) ->
  Args = [{"oauth_verifier", Verifier}],
  oauth_client:get_access_token(Client, URL, Args, header, Realm, Domain).

get_access_token(Client, URL, Verifier, Realm, Domain, RParams) ->
  Args = [{"oauth_verifier", Verifier}],
  oauth_client:get_access_token(Client, URL, Args, header, Realm, Domain, RParams).

get_verifier(Uri) ->
  [_,QueryStr] = string:tokens(Uri, "?"),
  AccessParams = oauth:uri_params_decode(QueryStr),
  proplists:get_value("oauth_verifier", AccessParams).

request_token_params(Client) ->
    oauth_client:request_token_params(Client).