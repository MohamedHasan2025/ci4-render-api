<?php

namespace App\Controllers;

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