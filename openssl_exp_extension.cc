/// Originally from the Native Client project (hello_tutorial.cc)
///
/// Copyright (c) 2012 The Native Client Authors. All rights reserved.
/// Use of this source code is governed by a BSD-style license that can be
/// found in the LICENSE file.

#include <cstdio>
#include <string>
#include "ppapi/cpp/instance.h"
#include "ppapi/cpp/module.h"
#include "ppapi/cpp/var.h"

#include <cstdio>
#include <cstring>
#include "openssl/dh.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"

// #define USE_SIGN_VERIFY_FLOW

namespace {
// The expected string sent by the browser.
const char* const kHelloString = "hello";

// #define USE_SIGN_VERIFY_FLOW

#if defined(USE_SIGN_VERIFY_FLOW)
const char* default_message  = "Default Test Message";
const EVP_MD *evp_md_sha1 = EVP_sha1();

class sign_result {
public:
    bool success;
    unsigned char *sig;
    size_t sig_len;

    char *error_string;

    void fetch_error_string() {
        ERR_load_crypto_strings();
        const char* err = ERR_reason_error_string(ERR_get_error());
        error_string = new char[strlen(err) + 1];
        strcpy(error_string, err);
        ERR_free_strings();
    }

    static sign_result* obtain() {
        sign_result *result = new sign_result();
        result->success = false;
        return result;
    }

    static void release(sign_result *result) {
        if (result->sig) {
            delete [] result->sig;
        }
        if (result->error_string) {
            delete [] result->error_string;
        }
        delete result;
    }
};

sign_result* sign(EVP_PKEY* priv_key, const char* message) {
    sign_result *result = sign_result::obtain();
    EVP_MD_CTX *md_ctx = NULL;
    int ret;

    md_ctx = EVP_MD_CTX_create();

    // Initialize EVP_MD_CTX with
    //  - a private key prepared above, and
    //  - a default engine (NULL).
    // SHA1 will be used for exact algorithm.
    // If EVP_PKEY_CTX object is needed we can specify the second argument.
    // The object is actually part of md_ctx, so we should not free it
    // manually. EVP_MD_CTX_destroy() will take care of freeing it.
    ret = EVP_DigestSignInit(md_ctx, NULL, evp_md_sha1, NULL, priv_key);
    if (ret != 1) {
        result->fetch_error_string();
        goto free;
    }

    // Hash the message. This function can be called multiple times with
    // different messages.
    ret = EVP_DigestSignUpdate(md_ctx, message, strlen(message)); 
    if (ret != 1) {
        result->fetch_error_string();
        goto free;
    }
    
    // Obtain the necessary length for signature.
    ret = EVP_DigestSignFinal(md_ctx, NULL, &result->sig_len);
    if (ret != 1) {
        result->fetch_error_string();
        goto free;
    }

    // Now obtain the content by calling EVP_DigestSignFinal() again
    // with data buffer with the specified length.
    result->sig = new unsigned char[result->sig_len];
    if (!EVP_DigestSignFinal(md_ctx, result->sig, &result->sig_len)) {
        result->fetch_error_string();
        goto free;
    }

    result->success = true;
 free:

    if (md_ctx) {
        EVP_MD_CTX_destroy(md_ctx);
    }
    return result;
}

#else

char* generate_key_pair() {
    RSA* rsa = NULL;
    BIO* bio_priv = NULL;
    BIO* bio_pub = NULL;
    BUF_MEM *bptr_priv = NULL;
    BUF_MEM *bptr_pub = NULL;
    char* ret = NULL;

    rsa = RSA_generate_key(1024, RSA_3, NULL, NULL);
    if (!RSA_check_key(rsa)) {
        goto free;
    }

    bio_priv = BIO_new(BIO_s_mem());
    bio_pub = BIO_new(BIO_s_mem());

    if (!PEM_write_bio_RSAPrivateKey(bio_priv, rsa, NULL, NULL, 0, 0, NULL)) {
        goto free;
    }

    if (!PEM_write_bio_RSA_PUBKEY(bio_pub, rsa)) {
    // if (!PEM_write_bio_RSAPublicKey(bio_pub, rsa)) {
        goto free;
    }
    BIO_get_mem_ptr(bio_priv, &bptr_priv);
    BIO_get_mem_ptr(bio_pub, &bptr_pub);
    ret = (char *)malloc(bptr_priv->length + bptr_pub->length + 1);
    memcpy(ret, bptr_priv->data, bptr_priv->length);
    memcpy(ret + bptr_priv->length, bptr_pub->data, bptr_pub->length);
    ret[bptr_priv->length + bptr_pub->length] = '\0';

 free:
    if (bio_pub) {
        BIO_free(bio_pub);
    }
    if (bio_priv) {
        BIO_free(bio_priv);
    }
    if (rsa) {
        RSA_free(rsa);
    }

    return ret;
}
#endif // USE_SIGN_VERIFY_FLOW
} // namespace

class OpenSSLExpInstance : public pp::Instance {
 public:
  /// The constructor creates the plugin-side instance.
  /// @param[in] instance the handle to the browser-side plugin instance.
  explicit OpenSSLExpInstance(PP_Instance instance) : pp::Instance(instance)
  {}
  virtual ~OpenSSLExpInstance() {}

  /// Handler for messages coming in from the browser via postMessage().  The
  /// @a var_message can contain anything: a JSON string; a string that encodes
  /// method names and arguments; etc.  For example, you could use
  /// JSON.stringify in the browser to create a message that contains a method
  /// name and some parameters, something like this:
  ///   var json_message = JSON.stringify({ "myMethod" : "3.14159" });
  ///   nacl_module.postMessage(json_message);
  /// On receipt of this message in @a var_message, you could parse the JSON to
  /// retrieve the method name, match it to a function call, and then call it
  /// with the parameter.
  /// @param[in] var_message The message posted by the browser.
  virtual void HandleMessage(const pp::Var& var_message) {
      if (!var_message.is_string()) {
          return;
      }
      std::string message = var_message.AsString();
      pp::Var var_reply;
      if (message == kHelloString) {

#if defined(USE_SIGN_VERIFY_FLOW)
          {
              EVP_PKEY* priv_key = NULL;
              sign_result* result = NULL;
              RSA* rsa = NULL;
              BIGNUM* f4 = NULL;
              int ret;
              
              f4 = BN_new();
              if (!f4) {
                  var_reply = pp::Var("BN_new() failed");
                  goto free;
              }
              BN_set_word(f4, RSA_F4);

              rsa = RSA_new();
              if (!rsa) {
                  var_reply = pp::Var("RSA_new() failed");
                  goto free;
              }
              ret = RSA_generate_key_ex(rsa, 1024, f4, NULL);
              if (ret != 1) {
                  var_reply = pp::Var("RSA_generate_key_ex() failed");
                  goto free;
              }
              var_reply = pp::Var("hello");

              ret = RSA_check_key(rsa);
              if (ret != 1) {
                  var_reply = pp::Var("RSA_check_key() failed");
                  goto free;
              }
              priv_key = EVP_PKEY_new();
              ret = EVP_PKEY_set1_RSA(priv_key, rsa);
              if (ret != 1) {
              var_reply = pp::Var("EVP_PKEY_set1_RSA() failed");
                  goto free;
              }

              result = sign(priv_key, default_message);
              if (result->success) {
                  var_reply = pp::Var("Successful");
              } else {
                  var_reply = pp::Var("Failure");
                  // var_reply = pp::Var(result->error_string);
              }
          free:
              if (priv_key) {
                  EVP_PKEY_free(priv_key);
              }
              if (f4) {
                  BN_clear_free(f4);
              }
              if (rsa) {
                  RSA_free(rsa);
              }
              if (result) {
                  sign_result::release(result);
              }
          }

#else
          char* data = generate_key_pair();
          if (data) {
              var_reply = pp::Var(data);
          } else {
              var_reply = pp::Var("Failed");
          }
#endif

          PostMessage(var_reply);

#if defined(USE_SIGN_VERIFY_FLOW)
#else
          if (data != NULL) {
              free(data);
          }
#endif
      }
  }
};

/// The Module class.  The browser calls the CreateInstance() method to create
/// an instance of your NaCl module on the web page.  The browser creates a new
/// instance for each <embed> tag with type="application/x-nacl".
class OpenSSLExpModule : public pp::Module {
 public:
  OpenSSLExpModule() : pp::Module() {}
  virtual ~OpenSSLExpModule() {}

  /// Create and return a OpenSSLExpInstance object.
  /// @param[in] instance The browser-side instance.
  /// @return the plugin-side instance.
  virtual pp::Instance* CreateInstance(PP_Instance instance) {
    return new OpenSSLExpInstance(instance);
  }
};

namespace pp {
/// Factory function called by the browser when the module is first loaded.
/// The browser keeps a singleton of this module.  It calls the
/// CreateInstance() method on the object you return to make instances.  There
/// is one instance per <embed> tag on the page.  This is the main binding
/// point for your NaCl module with the browser.
Module* CreateModule() {
    SSL_library_init();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();

    return new OpenSSLExpModule();
}
}  // namespace pp
