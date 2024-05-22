<?php

namespace Drupal\uceap_aes\Plugin\EncryptionMethod;

use Drupal\encrypt\EncryptionMethodInterface;
use Drupal\encrypt\Exception\EncryptException;
use Drupal\encrypt\Plugin\EncryptionMethod\EncryptionMethodBase;

/**
 * Class UceapAesEncryptionMethod.
 *
 * @EncryptionMethod(
 *   id = "uceap_aes",
 *   title = @Translation("UCEAP AES"),
 *   description = "Encryption based on AES-256 in CBC mode.",
 *   key_type_group = {"encryption"},
 *   can_decrypt = TRUE
 * )
 */
class UceapAesEncryptionMethod extends EncryptionMethodBase implements EncryptionMethodInterface {

  const CIPHER = 'aes-256-cbc';

  /**
   * {@inheritdoc}
   */
  public function checkDependencies($text = NULL, $key = NULL) {
    $errors = [];
    if (!function_exists('openssl_encrypt')) {
      $errors[] = $this->t('The openssl extension is required.');
    }
    return $errors;
  }

  /**
   * {@inheritdoc}
   */
  public function encrypt($text, $key, $options = []) {
    $iv_len = openssl_cipher_iv_length(self::CIPHER);
    $iv = openssl_random_pseudo_bytes($iv_len);
    $ciphertext = openssl_encrypt($text, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    return $iv . $ciphertext;
  }

  /**
   * {@inheritdoc}
   */
  public function decrypt($text, $key, $options = []) {
    $iv_len = openssl_cipher_iv_length(self::CIPHER);
    $iv = substr($text, 0, $iv_len);
    $ciphertext = substr($text, $iv_len);
    return openssl_decrypt($ciphertext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
  }

}
