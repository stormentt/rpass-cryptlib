#include "rpass-cryptlib.h"
#include <stdio.h>
#include <string.h>

int main() {
   if (init() < 0) {
       return 1;
   }

   unsigned char key[] = {
       0x8e, 0xa4, 0x0b, 0xdb, 0x95, 0xb3, 0x2f, 0x10, 0x56, 0x2f, 0x4f, 0x0e,
       0xf0, 0x0a, 0x3c, 0x95, 0x66, 0xa6, 0x86, 0x2f, 0x6d, 0x5f, 0xeb, 0x2e,
       0x93, 0x67, 0x4d, 0xd5, 0x66, 0x8d, 0xcb, 0xbe
   };

   enum RC e_rc = encrypt_file("testing/encrypted", "testing/plain", key);
   if (e_rc != SUCCESS) {
       fprintf(stderr, "%s\n", rc2str(e_rc));
       return 1;
   }
   enum RC d_rc = decrypt_file("testing/decrypted", "testing/encrypted", key);
   if (d_rc != SUCCESS) {
       fprintf(stderr, "%s\n", rc2str(d_rc));
       return 1;
   }

   char* p = "string encryption test succeeded";
   unsigned long long p_len = strlen(p);
   unsigned long long c_len = 0;
   unsigned long long d_len = 0;

   unsigned char* c = encrypt(p, p_len, &c_len, key);
   if (c == NULL) {
       return 1;
   }

   unsigned char* d = decrypt(c, c_len, &d_len, key);
   if (d == NULL) {
       return 1;
   }

   printf("p: %s\n", p);
   printf("d: %s\n", d);
}
