#include <stdio.h>
#include <locale.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/md4.h>

class NTLMCrack {
private:
  static char *hex_to_char(unsigned char c, char *buf) {
    unsigned char half = c >> 4;
    *(buf++) = half < 10 ? half + '0' : half - 10 + 'a';
    half = c & 0xF;
    *(buf++) = half < 10 ? half + '0' : half - 10 + 'a';
    return buf;
  }

  static unsigned char char_to_hex(char c) {
      return c >= '0' && c <= '9' ? c - '0' :
             c >= 'a' && c <= 'f' ? c - 'a' + 10 :
             c >= 'A' && c <= 'F' ? c - 'A' + 10 : 0xff;
  }

  static void convert_binary_string(std::string::iterator binary_string,
                                    size_t length,
                                    std::vector<unsigned char> &blob) {
    blob.resize(length / 2);
    auto it_binary = blob.begin();
    auto buf_end = binary_string + length;
    while (binary_string < buf_end) {
      unsigned char h = char_to_hex(*binary_string);
      ++binary_string;
      unsigned char l = char_to_hex(*binary_string);
      ++binary_string;
      unsigned char byte = (h != -1 && l != -1) ? (h << 4 | l) : 0xff;
      *it_binary = byte;
      ++it_binary;
    }
  }

  struct ntlm_response {
    std::vector<unsigned char> user_and_domain;
    std::vector<unsigned char> challenge;
    std::vector<unsigned char> auth_blob;
    std::vector<unsigned char> response;
    std::vector<unsigned char> blob_concat;

    bool load_file_from_samba(const char *fname) {
      const char prefix_userdomain[] = "UserAndDomain=";
      const char prefix_challenge[] = "Challenge=";
      const char prefix_auth[] = "Auth=";
      const char prefix_response[] = "Response=";
      int quad_flags = 0;
      std::ifstream infile(fname);
      for (std::string line; std::getline(infile, line); ) {

#define CONVERT(PREFIX, MEMBER, FLAG) \
        if (line.compare(0, sizeof(PREFIX) - 1, (PREFIX)) == 0) { \
          convert_binary_string(line.begin() + sizeof(PREFIX) - 1, \
                                line.size() - sizeof(PREFIX) + 1, \
                                (MEMBER)); \
          quad_flags |= (FLAG); \
        }

        CONVERT(prefix_userdomain, user_and_domain, 1);
        CONVERT(prefix_challenge, challenge, 2);
        CONVERT(prefix_auth, auth_blob, 4);
        CONVERT(prefix_response, response, 8);

        blob_concat.resize(0);
        blob_concat.reserve(challenge.size() + auth_blob.size());
        blob_concat.insert(blob_concat.end(),
                           challenge.begin(),
                           challenge.end());
        blob_concat.insert(blob_concat.end(),
                           auth_blob.begin(),
                           auth_blob.end());
      }
      return (quad_flags & 0xf) == 0xf;
    }
  };

  struct ntlm_response ntlm_response;
  unsigned char ntlm_hash[16];
  unsigned char ntlmv2_hash[16];
  unsigned char ntlmv2_response[16];
  std::vector<wchar_t> utf16_native_buffer;
  std::vector<unsigned short> utf16_ushort_buffer;

public:
  static void dump_hexstring(const unsigned char *data, int length) {
    char *buf = new char[length * 2 + 1];
    if (buf) {
      char *p = buf;
      int i;
      for (i = 0; i < length; ++i) {
        p = hex_to_char(data[i], p);
      }
      *p = 0;
      printf("%s\n", buf);
      delete [] buf;
    }
  }

  NTLMCrack() {
    utf16_native_buffer.resize(1024);
    utf16_ushort_buffer.resize(1024);
  }

  bool load_file_from_samba(const char *fname) {
    return ntlm_response.load_file_from_samba(fname);
  }

  bool test_password(const char *password_utf8) {
    size_t wchars = mbstowcs(nullptr, password_utf8, 0);
    if (utf16_native_buffer.size() < wchars + 1) {
      utf16_native_buffer.resize(wchars + 1);
    }
    wchars = mbstowcs(utf16_native_buffer.data(), password_utf8, wchars);
    if (wchars > 0) {
      if (utf16_ushort_buffer.size() < wchars) {
        utf16_ushort_buffer.resize(wchars);
      }
      std::copy(utf16_native_buffer.begin(),
                utf16_native_buffer.begin() + wchars,
                utf16_ushort_buffer.begin());
      MD4((unsigned char*)utf16_ushort_buffer.data(),
           sizeof(unsigned short) * wchars,
           ntlm_hash);
      //dump_hexstring(ntlm_hash, sizeof(ntlm_hash));
    }

    unsigned int hash_len = 0;
    HMAC(EVP_md5(),
         ntlm_hash,
         sizeof(ntlm_hash),
         ntlm_response.user_and_domain.data(),
         ntlm_response.user_and_domain.size(),
         ntlmv2_hash,
         &hash_len);
    //dump_hexstring(ntlmv2_hash, sizeof(ntlmv2_hash));

    HMAC(EVP_md5(),
         ntlmv2_hash,
         sizeof(ntlmv2_hash),
         ntlm_response.blob_concat.data(),
         ntlm_response.blob_concat.size(),
         ntlmv2_response,
         &hash_len);
    //dump_hexstring(ntlmv2_response, sizeof(ntlmv2_response));

    return ntlm_response.response.size() == sizeof(ntlmv2_response)
           && std::equal(ntlm_response.response.begin(),
                         ntlm_response.response.end(),
                         ntlmv2_response);
  }
};

void show_usage() {
  printf("Usage: bf -f <samba log> [-p password] [-l <password list>]\n\n");
}

int main(int argc, char *argv[]) {
  const char *logfile = nullptr;
  const char *pwfile = nullptr;
  const char *password = nullptr;
  int opt;
  while ((opt = getopt(argc, argv, "f:p:l:")) != -1) {
    switch (opt) {
    case 'f':
      logfile = optarg;
      break;
    case 'p':
      password = optarg;
      break;
    case 'l':
      pwfile = optarg;
      break;
    default:
      // ignore unknown arguments
      break;
    }
  }

  if (logfile == nullptr) {
    show_usage();
    exit(1);
  }

  NTLMCrack cracker;
  if (cracker.load_file_from_samba(logfile)) {
    setlocale(LC_ALL, "en_US.utf8");
    bool succeeded = false;
    if(password != nullptr) {
      succeeded = cracker.test_password(password);
      printf("%s is %s.\n",
        password, (succeeded ? "matched" : "not matched"));
    }
    if (pwfile != nullptr) {
      std::ifstream infile(pwfile);
      int cnt = 0;
      bool succeeded = false;
      clock_t t = clock();
      for (std::string line; std::getline(infile, line); ) {
        ++cnt;
        if (cracker.test_password(line.c_str())) {
          succeeded = true;
          printf("%s\n", line.c_str());
          break;
        }
      }
      t = clock() - t;
      if (!succeeded) {
        printf("No matching password in %s.\n", pwfile);
      }
      printf("Tried %d strings in %d msec.\n",
             cnt,
             (int)(t * 1000 / CLOCKS_PER_SEC));
    }
  }
  exit(0);
}