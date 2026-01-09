<?php

namespace App\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\Model;
use CodeIgniter\Database\Database;
    
class HDAPITools
{
    protected $digest = 'SHA512';
    protected array $digestSize = [
        'SHA224' => 28,
        'SHA256' => 32,
        'SHA384' => 48,
        'SHA512' => 64,
    ];
    protected $cipher = 'AES-256-CTR';

    public string $key = '43db77fc754ca6d2a9f9311860c534330a1d13fa045bb037f82af772468230d0';
    protected bool $rawData = true;

    public function authenticate()
    {        
        $hdapitools = new HDAPITools();

        //$jsonData = '{"authcode":"79Qdj8y5+Gy8Y=5KEW2kYz567IHBPB7N07TfjPR3qH8Y"}';    
        
        $jsonData = '{
                        "authcode": "79Qdj8y5+Gy8Y=5KEW2kYz567IHBPB7N07TfjPR3qH8Y",
                        "thirdparty": {
                            "un": "hdportallogin1@gmail.com",
                            "pw": "RWry0L=bjvGm",
                            "data": "a3ca2dc36707ce62a4c1647fc1aac9acaf1c364e7bdac69f50ffa150852b8a5e26eec06fcb972cc9407dee472e76f5fdadbcefe38d43305c47c1b6f4b6a8c95c352d0ec1675825987078165abc68763b34face56afa80f64509f230a1e1dbc33c139bbf52846c771887efcec544cd4b65c4641009fc7bd673ff23436351ba7503c401846f3ce84b1cd4485"
                        }
                    }';

        $data = json_decode($jsonData, true);

        $encryptedMessage = $hdapitools->encrypt(json_encode($data));

        return $encryptedMessage;
    }

    public function encrypt($data)
    {
        if (empty($this->key)) {
            return 'Key Required';
        }
        $encryptKey = hash_hkdf($this->digest, $this->key, 0, 'HDencrypt2025@');

        $iv = ($ivSize = openssl_cipher_iv_length($this->cipher)) ? openssl_random_pseudo_bytes($ivSize) : null;

        $data = openssl_encrypt($data, $this->cipher, $encryptKey, OPENSSL_RAW_DATA, $iv);

        if ($data === false) {
            throw EncryptionException::forEncryptionFailed();
        }
        $result = $this->rawData ? $iv . $data : base64_encode($iv . $data);

        $authKey = hash_hkdf($this->digest, $this->key, 0, '2025$heliD');

        $hmacKey = hash_hmac($this->digest, $result, $authKey, $this->rawData);
        
        return bin2hex($hmacKey . $result);
    }

    public function decrypt($data)
    {        
        //echo 'Data: '. $data;
        if (empty($this->key)) {
            return 'Key Required';
        }
        $data = hex2bin($data);

        $authKey = hash_hkdf($this->digest, $this->key, 0, '2025$heliD');
        $hmacLength = $this->rawData ?
            $this->digestSize[$this->digest] :
            $this->digestSize[$this->digest] * 2;
        $hmacKey = substr($data, 0, $hmacLength);
        $data = substr($data, $hmacLength);
        $hmacCalc = hash_hmac($this->digest, $data, $authKey, $this->rawData);
        if (!hash_equals($hmacKey, $hmacCalc)) {
            return 'Decryption Failed';
        }
        $data = $this->rawData ? $data : base64_decode($data, true);
        if ($ivSize = openssl_cipher_iv_length($this->cipher)) {
            $iv = substr($data, 0, $ivSize);
            $data = substr($data, $ivSize);
        } else {
            $iv = null;
        }
        $encryptKey = hash_hkdf($this->digest, $this->key, 0, 'HDencrypt2025@');
        return openssl_decrypt($data, $this->cipher, $encryptKey, OPENSSL_RAW_DATA, $iv);
    }

    public function tpEncrypt($data, $key)
    {

        if (empty($key)) {
            return 'Key Required';
        }
        $encryptKey = hash_hkdf($this->digest, $key, 0, 'HDencrypt2025@');
        $iv = ($ivSize = openssl_cipher_iv_length($this->cipher)) ? openssl_random_pseudo_bytes($ivSize) : null;

        $data = openssl_encrypt($data, $this->cipher, $encryptKey, OPENSSL_RAW_DATA, $iv);

        if ($data === false) {
            throw EncryptionException::forEncryptionFailed();
        }
        $result = $this->rawData ? $iv . $data : base64_encode($iv . $data);
        $authKey = hash_hkdf($this->digest, $key, 0, '2025$heliD');
        $hmacKey = hash_hmac($this->digest, $result, $authKey, $this->rawData);
        return bin2hex($hmacKey . $result);
    }

    public function tpDecrypt($data, $key)
    {
        if (empty($key)) {
            return 'Key Required';
        }
        $data = hex2bin($data);
        $authKey = hash_hkdf($this->digest, $key, 0, '2025$heliD');
        $hmacLength = $this->rawData ?
            $this->digestSize[$this->digest] :
            $this->digestSize[$this->digest] * 2;
        $hmacKey = substr($data, 0, $hmacLength);
        $data = substr($data, $hmacLength);
        $hmacCalc = hash_hmac($this->digest, $data, $authKey, $this->rawData);
        if (!hash_equals($hmacKey, $hmacCalc)) {
            return 'Decryption Failed';
        }
        $data = $this->rawData ? $data : base64_decode($data, true);
        if ($ivSize = openssl_cipher_iv_length($this->cipher)) {
            $iv = substr($data, 0, $ivSize);
            $data = substr($data, $ivSize);
        } else {
            $iv = null;
        }
        $encryptKey = hash_hkdf($this->digest, $key, 0, 'HDencrypt2025@');
        return openssl_decrypt($data, $this->cipher, $encryptKey, OPENSSL_RAW_DATA, $iv);
    }

    public function getEncryptionKey() 
    {
        return $this->key;
    }

    public function addMinutes($time, $minutesToAdd)
    {
          // Split date/time and timezone
        $parts = explode('+', $time);
        $timePart = $parts[0];       // "2026-01-30T09:20:00"
        $tzOffset = isset($parts[1]) ? $parts[1] : '00:00';

        // Convert time to timestamp in UTC
        list($date, $time) = explode('T', $timePart);
        list($hour, $min, $sec) = explode(':', $time);

        // Convert offset to seconds
        list($tzHour, $tzMin) = explode(':', $tzOffset);
        $offsetSeconds = ($tzHour * 3600 + $tzMin * $minutesToAdd);

        // Subtract offset to get UTC timestamp
        $timestamp = strtotime("$date $hour:$min:$sec") - $offsetSeconds;

        // Add 60 minutes
        $timestamp += 60 * $minutesToAdd;

        // Add offset back to get original timezone
        $timestamp += $offsetSeconds;

        // Format back to ISO-8601
        $newDateTime = gmdate('Y-m-d\TH:i:s', $timestamp) . '+' . $tzOffset;

        return $newDateTime;
    }  
}

class ApiController extends Controller
{      
    public function sendAvailability()
    {
        // Get PHP-auth credentials sent via Basic Auth
        $username = $this->request->getServer('PHP_AUTH_USER');
        $password = $this->request->getServer('PHP_AUTH_PW');
        
        $username = 'hdportallogin1@gmail.com';
        $password = 'RWry0L=bjvGm';

        // Get query parameters
        $params = $this->request->getGet();

        $productId = $params['productId'] ?? null;
        $from      = $params['fromDateTime'] ?? null;
        $to        = $params['toDateTime'] ?? null;        
        $pax       = $params['pax'] ?? 2; // default 2

        if (!$username || !$password) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Missing Basic Auth credentials'
            ])->setStatusCode(401);
        }
        
        if (!$productId || !$from || !$to) {
            return $this->response->setJSON([
                'status' => 'error',
                'message' => 'Missing required parameters'
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
        list($dateFrom, $timeFrom) = explode('T', $from);
        list($dateTo, $timeTo) = explode('T', $to);

        $jsonData_Times = json_encode([
                            "sdate" => $dateFrom,
                            "edate" => $dateTo,
                            "id"    => $productId,
                            "pax"   => (string) $pax
                        ]);
                    
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
            $count = 1;
            foreach ($item['pr'] as $price) {
                if ($count <= 2) {
                    $retailPrices[] = [
                    'category' => strtoupper($price['group'] == 't-14400' ? 'ADULT' : 'CHILD'),
                    'price'    => 710//(float) $price['price']
                ];
                    $count++;   
                }                
            }

            $availabilities[] = [
                'dateTime' => $item['dt'],
                'productId' => $item['id'].'-'.$item['fn'],
                //'productId' => $item['id'],
                'cutoffSeconds' => $cutoffSeconds,
                'vacancies' => $item['avs'],
                'currency' => 'AED',
                'pricesByCategory' => [
                    'retailPrices' => $retailPrices
                ]
            ];

            // $availabilities[] = [
            //         'dateTime' => $item['dt'], // ISO 8601 datetime
            //         'productId' => $item['id'],
            //         'cutoffSeconds' => (int) $cutoffSeconds,
            //         'currency' => 'AED',

            //         'vacanciesByCategory' => [
            //             [
            //                 'category'   => 'ADULT',
            //                 'vacancies'  => (int) $item['avs'],
            //             ],
            //             [
            //                 'category'   => 'CHILD',
            //                 'vacancies'  => (int) $item['avs'],
            //             ],
            //         ],
            //     ];
        }

        //✅ Final response
        $response = [
            'data' => [
                'availabilities' => $availabilities
            ]
        ];

        return $this->response->setJSON($response);
    }

    public function getFlightNumber($jwt, $dateTime, $productId, $pax, $username, $password)
    {        
        list($date, $time) = explode('T', $dateTime);
        
        // Now prepare request data for times API
        $jsonData_Times = json_encode([
                            "sdate" => $date,
                            "edate" => $date,
                            "id"    => $productId,
                            "pax"   => (string) $pax
                        ]);
                                   
        $data_Times = json_decode($jsonData_Times, true);
        
        $hdapitools = new HDAPITools();

        $encryptedMessage_Times = $hdapitools->encrypt(json_encode($data_Times));
        
        $jsonData = [
                        'data' => $encryptedMessage_Times,
                        'jwt' => $jwt
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

            if($item['dt'] == $dateTime) {
                return $item['fn'];
            }
        }
        return null;
    }  

    public function reserveAvailability()
    {
        // Get PHP-auth credentials sent via Basic Auth
        $username = $this->request->getServer('PHP_AUTH_USER');
        $password = $this->request->getServer('PHP_AUTH_PW');

        $username = 'hdportallogin1@gmail.com';
        $password = 'RWry0L=bjvGm';

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

        $fn = $this->getFlightNumber(
                                        $data_jwt->jwt, 
                                        $data['dateTime'], 
                                        $data['productId'], 
                                        $totalPax,
                                        $username,
                                        $password   
                                    );

        if (!$fn) {       
                return $this->response->setJSON([
                        'errorCode' => 'NO_AVAILABILITY',
                        'errorMessage' => 'This activity is sold out; no availability found for the selected date/time.'
                    ]);
        }   

        $id = $data['productId'];           
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

        $username = 'hdportallogin1@gmail.com';
        $password = 'RWry0L=bjvGm';

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

        $username = 'hdportallogin1@gmail.com';
        $password = 'RWry0L=bjvGm';

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
