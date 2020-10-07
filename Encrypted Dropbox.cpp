#include <stdio.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <assert.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>
using namespace std;
static const char* change_base ;
std::string bscng(const unsigned char* first, const unsigned char* last){
    int z = 0;
    int l = 0;
    while (first != last && *first == 0) {
        first++;
        z++;
    }           // for size checking and space providing
    int size = (last - first) * 138 / 100 + 1; // round off value.
    vector <unsigned char> byt58(size);// the result array
    while (first != last) {
    int next = *first;
    int i = 0;   // Now the main encoding begins
    std::vector<unsigned char>::reverse_iterator loop = byt58.rbegin();
    for(loop;(next!=0||i<l)&&(loop!=byt58.rend());loop++,i++){
        next += 256 * (*loop);
        *loop = next % 58;
        next /= 58;
    }
    assert(next == 0);
    l = i;
    first++;
    }           // leading zeroes not needed so removing
    std::vector<unsigned char>::iterator loop = byt58.begin()+(size-l); 
    while (loop != byt58.end() && *loop == 0)loop++;
    std::string ret;                    //copying into ret
    ret.reserve(z + (byt58.end() - loop));
    ret.assign(z, '1');
    while (loop != byt58.end())ret += change_base[*(loop++)];
    return ret;                         //result
}
bool generate_key()                             //key generator
{
int check = 0;                                  //initialising
RSA *r = NULL;
BIGNUM *bignum = NULL;
BIO *bp_public = NULL, *bp_private = NULL;
unsigned long   e = RSA_F4;
bignum = BN_new();                              //generating the key
check = BN_set_word(bignum,e);
r = RSA_new();
check = RSA_generate_key_ex(r, 2048, bignum, NULL);
bp_public = BIO_new_file("public.pem", "w+");   //saving public key
check = PEM_write_bio_RSAPublicKey(bp_public, r);
bp_private = BIO_new_file("private.pem", "w+"); //saving rivate key
check=PEM_write_bio_RSAPrivateKey(bp_private,r,NULL,NULL,0,NULL,NULL);
free_all:                                       // free everything
BIO_free_all(bp_public);
BIO_free_all(bp_private);
RSA_free(r);
BN_free(bignum);
return check;
}
int main() 
{   
    change_base="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    generate_key();                         //generating key
    char file[] = "public.pem";     
    BIO *pubkey = NULL;
    pubkey = BIO_new_file(file, "r");
    const unsigned char *a = (const unsigned char *)pubkey;
    int t = sizeof(pubkey);                 //first hash
    unsigned char hash[32] = {0};
    SHA256(a, t, hash);
    unsigned char ripemd[21] = {0};         //ripemd of first hash
    RIPEMD160(hash, sizeof(hash), ripemd+1);
    unsigned char hash2[32] = {0};          //second hash
    SHA256(ripemd, sizeof(ripemd), hash2);
    unsigned char hash3[32] = {0};          //third hash
    SHA256(hash2, sizeof(hash2), hash3);
    unsigned char base[25] = {0};           //verifying checksum
    memcpy(base, ripemd, sizeof(ripemd));
    memcpy(base +21, hash3, 4*sizeof(unsigned char));
    cout << "corrseponding address is" <<endl;
    cout << bscng(base, base +25) << endl;  //after final encoding
 
    return 0;
}