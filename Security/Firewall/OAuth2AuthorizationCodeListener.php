<?php

namespace OAuth2\ClientBundle\Security\Firewall;

use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\HttpFoundation\Request;
use Donato\HttpBundle\Guzzle\Client;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use OAuth2\ClientBundle\Security\Authentication\Token\OAuth2Token;

class OAuth2AuthorizationCodeListener extends AbstractAuthenticationListener
{
    protected $serverAuthorizeUri;
    protected $serverTokenUri;
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $scope;
    protected $validateSSL;

    public function setServer(array $oauth2_server)
    {
        $this->serverAuthorizeUri = $oauth2_server['authorize_uri'];
        $this->serverTokenUri = $oauth2_server['token_uri'];
        $this->validateSSL = $oauth2_server['validate_ssl'];
    }
    
    public function setClient(array $oauth2_client)
    {
        $this->clientId = $oauth2_client['client_id'];
        $this->clientSecret = $oauth2_client['client_secret'];
        $this->redirectUri = $oauth2_client['redirect_uri'];
        $this->scope = $oauth2_client['scope'];
    }

    /**
     * {@inheritDoc}
     */
    public function requiresAuthentication(Request $request)
    {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        // Look for an authorization code
        if($request->query->has('code')) {
            $session = $request->getSession();
            // Do with have an authorization code instead?
            // and do the states match?
            if ($session->get('state') == $request->query->get('state')) {
                // Swap authorization code for access token
                $tokenData = array();

                $client = new Client();
                if ($this->validateSSL === false) {
                    $client = new Client(null, array('ssl.certificate_authority' => FALSE));
                }
                $api_request = $client->post(
                    $this->serverTokenUri,
                    array(),
                    array(
                        'grant_type' => 'authorization_code',
                        'code' => $request->query->get('code'),
                        'client_id' => $this->clientId,
                        'client_secret' => $this->clientSecret,
                        'redirect_uri' => $this->redirectUri,
                    ),
                    array(
                        'timeout' => 2,
                        'connect_timeout' => 2,
                    )
                );

                try {
                    $response = $api_request->send();
                    $tokenData = $response->json();
                }
                catch(\Exception $e)
                {
                    throw new AuthenticationException('Authorization Code Invalid');
                }

                if (isset($tokenData) && is_array($tokenData)) {
                    $token = new OAuth2Token();
                    $token->setAccessToken($tokenData['access_token']);

                    if (isset($tokenData['refresh_token'])) {
                        $token->setRefreshToken($tokenData['refresh_token']);
                    }

                    $authToken = $this->authenticationManager->authenticate($token);

                    if (isset($authToken)) return $authToken;
                }
            }
        }

        return null;
    }
}