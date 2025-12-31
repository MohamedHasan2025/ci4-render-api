<?php

namespace App\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Psr\Log\LoggerInterface;

class ApiController extends Controller
{      
    public function sendAvailability()
    {
        // Get PHP-auth credentials sent via Basic Auth
        $username = $this->request->getServer('PHP_AUTH_USER');
        $password = $this->request->getServer('PHP_AUTH_PW');

        if (!$username || !$password) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Missing Basic Auth credentials'
            ])->setStatusCode(401);
        }

        $hdapitools = new HDAPITools();

        $encryptedAuthMessage = $hdapitools->authenticate();

        $jsonData_Auth = [
                            'data' => $encryptedAuthMessage
                        ];

        // Call authenticate internal API with Basic Auth from incoming request
        $client = \Config\Services::curlrequest();
        $response = $client->post('https://api.helidubai.com/1/credit/authenticate', [
            'auth' => [$username, $password],
            'json' => $jsonData_Auth
        ]);

        $data_jwt = json_decode($response->getBody());

        // Now prepare request data for times API
        $jsonData_Times = '{    
                                "sdate":"2026-03-02",
                                "edate":"2026-03-02",
                                "id":"R1001",
                                "pax":"1"
                            }';
                    
        $data_Times = json_decode($jsonData_Times, true);

        $encryptedMessage_Times = $hdapitools->encrypt(json_encode($data_Times));

        $jsonData = [
                        'data' => $encryptedMessage_Times,
                        'jwt' => $data_jwt->jwt
                    ];

        $client = \Config\Services::curlrequest();
        $response_Times = $client->post('https://api.helidubai.com/1/credit/times', 
                                        [
                                            'auth' => [$username, $password],
                                            'json' => $jsonData
                                        ]);
        
        // Decrypt response (this returns JSON string)
        $decryptedResponse = $hdapitools->decrypt(json_decode($response_Times->getBody())->data);

        // // Decode decrypted JSON into associative array
        $source = json_decode($decryptedResponse, true);

        // Safety check
        if (!is_array($source)) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Invalid decrypted response'
            ])->setStatusCode(500);
        }

        $availabilities = [];

        foreach ($source as $item) {

            // Calculate cutoffSeconds (dt - co)
            $dt = $item['dt'];
            $dt = str_replace(' ', '', $dt);
            list($date, $time) = explode('T', $dt);
            list($hour, $min, $sec) = explode(':', $time);
            $timestampDt = strtotime("$date $hour:$min:$sec UTC");

            // Process cutoff time
            $co = $item['co'];
            $co = str_replace(' ', '', $co);
            list($cDate, $cTime) = explode('T', $co);
            list($cHour, $cMin, $cSec) = explode(':', $cTime);
            $timestampCo = strtotime("$cDate $cHour:$cMin:$cSec UTC");

            // Calculate cutoffSeconds
            $cutoffSeconds = $timestampDt - $timestampCo;

            // Build prices
            $retailPrices = [];
            foreach ($item['pr'] as $price) {
                $retailPrices[] = [
                    'category' => strtoupper($price['group'] == 't-14400' ? 'ADULT' : 'CHILD'),
                    'price'    => (float) $price['price']
                ];
            }

            $availabilities[] = [
                'dateTime' => $item['dt'],
                'productId' => $item['id'].'-'.$item['fn'],
                'cutoffSeconds' => $cutoffSeconds,
                'vacancies' => $item['avs'],
                'currency' => 'AED',
                'pricesByCategory' => [
                    'retailPrices' => $retailPrices
                ]
            ];
        }

        //✅ Final response
        $response = [
            'data' => [
                'availabilities' => $availabilities
            ]
        ];

        return $this->response->setJSON($response);
    }

    public function reserveAvailability()
    {
        // Get PHP-auth credentials sent via Basic Auth
        $username = $this->request->getServer('PHP_AUTH_USER');
        $password = $this->request->getServer('PHP_AUTH_PW');

        if (!$username || !$password) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Missing Basic Auth credentials'
            ])->setStatusCode(401);
        }

        $hdapitools = new HDAPITools();

        $encryptedAuthMessage = $hdapitools->authenticate();

        $jsonData_Auth = [
                            'data' => $encryptedAuthMessage
                        ];

        // Call authenticate internal API with Basic Auth from incoming request
        $client = \Config\Services::curlrequest();
        $response = $client->post('https://api.helidubai.com/1/credit/authenticate', [
            'auth' => [$username, $password],
            'json' => $jsonData_Auth
        ]);

        $data_jwt = json_decode($response->getBody());
        
        // Get JSON data from request body
        $json = $this->request->getJSON(true);
        $data = $json['data'] ?? null;        

        // Prepare JSON for external API
        $jsonData = ["data" => $data];

        $totalPax = 0;
        foreach ($jsonData['data']['bookingItems'] as $item) {
            $totalPax += (int) $item['count'];
        }

        list($id, $fn) = explode('-', $data['productId'], 2);           
        $br = $data['gygBookingReference'];  
        $dateTime = $data['dateTime'];
        $expiryDateTime = $hdapitools->addMinutes($data['dateTime'], 60);
        
        // Now prepare request data for reserve API
        $requestPayload = [
                            'fn'  => $fn,                    
                            'id'  => $id,                
                            'p'   => $totalPax,     
                            'br'  => $br,                    
                            'r'   => 'remarks',              
                            'w1'  => '90',                   
                            'tnc' => '1'                     
                        ];

        $data_Reserve = json_encode($requestPayload, true);

        $encryptedMessage_Reserve = $hdapitools->encrypt($data_Reserve);

        $jsonData = [
                        'data' => $encryptedMessage_Reserve,
                        'jwt' => $data_jwt->jwt
                    ];

        $client = \Config\Services::curlrequest();
        $response_Reserve = $client->post('https://api.helidubai.com/1/credit/reserve', [
            'auth' => [$username, $password],
            'json' => $jsonData
        ]);
                
        $responseArray = json_decode($response_Reserve->getBody(), true);

        if (
                isset($responseArray['error']) &&
                is_array($responseArray['error']) &&
                !empty($responseArray['error'])
            ) {
                return $this->response->setJSON([
                        'error' => $responseArray['error']
                    ])->setStatusCode(500);
            }

        // Decrypt response (this returns JSON string)
        $decryptedResponse = $hdapitools->decrypt(json_decode($response_Reserve->getBody())->data);

        // Decode decrypted JSON into associative array
        $source = json_decode($decryptedResponse, true);

        // Safety check
        if (!is_array($source)) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Invalid decrypted response'
            ])->setStatusCode(500);
        }       

        // Final response
        $response = [
            'data' => [
                'reservationReference' => $source['bid'],
                'reservationExpiration' => $expiryDateTime
            ]
        ];  

        return $this->response->setJSON($response);
    }

    public function cancelReservation()
    {
        // Get PHP-auth credentials sent via Basic Auth
        $username = $this->request->getServer('PHP_AUTH_USER');
        $password = $this->request->getServer('PHP_AUTH_PW');

        if (!$username || !$password) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Missing Basic Auth credentials'
            ])->setStatusCode(401);
        }

        $hdapitools = new HDAPITools();

        $encryptedAuthMessage = $hdapitools->authenticate();

        $jsonData_Auth = [
                            'data' => $encryptedAuthMessage
                        ];

        // Call authenticate internal API with Basic Auth from incoming request
        $client = \Config\Services::curlrequest();
        $response = $client->post('https://api.helidubai.com/1/credit/authenticate', [
            'auth' => [$username, $password],
            'json' => $jsonData_Auth
        ]);

        $data_jwt = json_decode($response->getBody());
                                      
        // Get JSON data from request body
        $json = $this->request->getJSON(true);
        $data = $json['data'] ?? null;  

        $bid = isset($data['reservationReference']) ? $data['reservationReference'] : $data['bookingReference'];
        $br = $data['gygBookingReference'];  
        $cr = 'Not Confirmed';
        
        // Now prepare request data for reserve API
        $requestPayload = [
                            'bid'  => $bid,                    
                            'br'  => $br,                
                            'cr'   => $cr                  
                        ];

        $data_Reserve = json_encode($requestPayload, true);

        $encryptedMessage_Reserve = $hdapitools->encrypt($data_Reserve);

        $jsonData = [
                        'data' => $encryptedMessage_Reserve,
                        'jwt' => $data_jwt->jwt
                    ];

        $client = \Config\Services::curlrequest();
        $response_Reserve = $client->post('https://api.helidubai.com/1/credit/cancel', [
            'auth' => [$username, $password],
            'json' => $jsonData
        ]);
                
        $responseArray = json_decode($response_Reserve->getBody(), true);

        if (
                isset($responseArray['error']) &&
                is_array($responseArray['error']) &&
                !empty($responseArray['error'])
            ) {
                return $this->response->setJSON([
                        'error' => $responseArray['error']
                    ])->setStatusCode(500);
            }

        // Decrypt response (this returns JSON string)
        $decryptedResponse = $hdapitools->decrypt(json_decode($response_Reserve->getBody())->data);

        // Decode decrypted JSON into associative array
        $source = json_decode($decryptedResponse, true);

        // Safety check
        if (!is_array($source)) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Invalid decrypted response'
            ])->setStatusCode(500);
        }       

        // Final response
        $response = [
            'data' => ''
        ];  

        return $this->response->setJSON($response);
    }

    public function bookReservation()
    {
        // Get PHP-auth credentials sent via Basic Auth
        $username = $this->request->getServer('PHP_AUTH_USER');
        $password = $this->request->getServer('PHP_AUTH_PW');

        if (!$username || !$password) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Missing Basic Auth credentials'
            ])->setStatusCode(401);
        }

        $hdapitools = new HDAPITools();

        $encryptedAuthMessage = $hdapitools->authenticate();

        $jsonData_Auth = [
                            'data' => $encryptedAuthMessage
                        ];

        // Call authenticate internal API with Basic Auth from incoming request
        $client = \Config\Services::curlrequest();
        $response = $client->post('https://api.helidubai.com/1/credit/authenticate', [
            'auth' => [$username, $password],
            'json' => $jsonData_Auth
        ]);

        $data_jwt = json_decode($response->getBody());
                                      
        // Get JSON data from request body
        $json = $this->request->getJSON(true);
        $data = $json['data'] ?? null;        

        // Prepare JSON for external API
        $jsonData = ["data" => $data];
        
        $bid = $data['reservationReference'];     
        $br = $data['gygBookingReference'];  
        $name = $data['travelers'][0]['firstName']. ' '. $data['travelers'][0]['lastName'];  
        $email = $data['travelers'][0]['email'];
        $phone = $data['travelers'][0]['phoneNumber'];

        // Now prepare request data for reserve API
        $requestPayload = [
                            'bid'  => $bid,                    
                            'br'  => $br,                
                            'n'   => $name,     
                            'p'   => $phone,                    
                            'e'   => $email,                
                            'tnc' => '1'                     
                        ];

        $data_Reserve = json_encode($requestPayload, true);

        $encryptedMessage_Reserve = $hdapitools->encrypt($data_Reserve);

        $jsonData = [
                        'data' => $encryptedMessage_Reserve,
                        'jwt' => $data_jwt->jwt
                    ];

        $client = \Config\Services::curlrequest();
        $response_Reserve = $client->post('https://api.helidubai.com/1/credit/confirm', [
            'auth' => [$username, $password],
            'json' => $jsonData
        ]);
                
        $responseArray = json_decode($response_Reserve->getBody(), true);

        if (
                isset($responseArray['error']) &&
                is_array($responseArray['error']) &&
                !empty($responseArray['error'])
            ) {
                return $this->response->setJSON([
                        'error' => $responseArray['error']
                    ])->setStatusCode(500);
            }

        // Decrypt response (this returns JSON string)
        $decryptedResponse = $hdapitools->decrypt(json_decode($response_Reserve->getBody())->data);

        // Decode decrypted JSON into associative array
        $source = json_decode($decryptedResponse, true);

        // Safety check
        if (!is_array($source)) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Invalid decrypted response'
            ])->setStatusCode(500);
        }       

        // Final response
        $response = [
            'data' => $source
        ];

        return $this->response->setJSON($response);
    }
}
