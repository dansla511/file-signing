#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>

void generate_keys(){

    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* p_minus_one = BN_new();
    BIGNUM* q_minus_one = BN_new();
    BIGNUM* gcd_num = BN_new();
    BIGNUM* phi_n = BN_new();
    BIGNUM* d;
    BIGNUM* e = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    int error;

    BN_dec2bn(&e, "65537");
    BN_one(p_minus_one);
    BN_one(q_minus_one);
    BN_generate_prime_ex(p, 1024, false, NULL, NULL, NULL);
    BN_generate_prime_ex(q, 1024, false, NULL, NULL, NULL);
    if((error = BN_sub(p_minus_one, p, p_minus_one)) == 0){
        printf("error in big number subtraction\n");
    }

    if(error == 0 || (error = BN_sub(q_minus_one, q, q_minus_one)) == 0){
        printf("error in big number subtraction\n");
    }

    if(error == 0 || (error = BN_mul(n, p, q, ctx)) == 0){
        printf("error in big number multiplication\n");
    }

    if(error == 0 || (error = BN_mul(phi_n, p_minus_one, q_minus_one, ctx)) == 0){
        printf("error in big number multiplication\n");
    }

    if(error == 0 || (error = BN_gcd(gcd_num, p_minus_one, q_minus_one, ctx)) == 0){
        printf("error in big number gcd\n");
    }

    if(error == 0 || (error = BN_div(phi_n, NULL, phi_n, gcd_num, ctx)) == 0){
        printf("error in big number division\n");
    }

    if(error == 0 || (d = BN_mod_inverse(NULL, e, phi_n, ctx)) == NULL){
        printf("error in big number mod inversion\n");
    }

    if(error != 0 && d != NULL){
        FILE* pub = fopen("public.txt", "w");
        FILE* pri = fopen("private.txt", "w");

        BN_print_fp(pub, n);
        fprintf(pub, "+");
        BN_print_fp(pub, e);
        BN_print_fp(pri, d);

        fclose(pub);
        fclose(pri);
    }

    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(n);
    BN_clear_free(e);
    BN_clear_free(d);
    BN_clear_free(p_minus_one);
    BN_clear_free(q_minus_one);
    BN_clear_free(gcd_num);
    BN_clear_free(phi_n);
    BN_CTX_free(ctx);

    printf("Kluce vygenerovane! Kluce su v private.txt a public.txt\n");

}

void validate_file(char* file_name){

    if(access("public.txt", F_OK) != 0){
        printf("Verejny kluc nenajdeny, prerusujem program\n");
        generate_keys();
    }

    if(access(file_name, F_OK) != 0){
        printf("Subor nenajdeny, prerusujem program\n");
        return;
    }

    if(access("signature.txt", F_OK) != 0){
        printf("Podpis nenajdeny, prerusujem program\n");
        return;
    }

    FILE* pub = fopen("public.txt", "r");
    FILE* file = fopen(file_name, "r");
    FILE* sig = fopen("signature.txt", "r");

    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *file_contents = (unsigned char*)malloc(fsize);
    fread(file_contents, fsize, 1, file);
    fclose(file);

    unsigned char *hash = SHA1(file_contents, fsize, NULL);

    fseek(sig, 0, SEEK_END);
    long signature_size = ftell(sig);
    fseek(sig, 0, SEEK_SET);

    char *signature_file = (char*)malloc(signature_size+1);
    fread(signature_file, signature_size, 1, sig);
    fclose(sig);

    signature_file[signature_size] = '\0';

    long pub_key_size = 0;
    long exponent_size = 0;
    int switch_to_exp = 0;
    char c;

    do{
        c = fgetc(pub);
        if(c == '+'){
            switch_to_exp = 1;
            continue;
        }

        if(switch_to_exp == 1){
            exponent_size++;
        }
        else{
            pub_key_size++;
        }
    }
    while(c != EOF);

    fseek(pub, 0, SEEK_SET);

    char* public_key_file = (char*)malloc(pub_key_size+1);
    char* exponent_file = (char*)malloc(exponent_size+1);

    fread(public_key_file, pub_key_size, 1, pub);
    fgetc(pub);
    fread(exponent_file, exponent_size, 1, pub);
    fclose(pub);

    public_key_file[pub_key_size] = '\0';
    exponent_file[exponent_size] = '\0';

    BIGNUM* hash_num_have = BN_new();
    BIGNUM* exponent = BN_new();
    BIGNUM* public_key = BN_new();
    BIGNUM* signature_recv = BN_new();
    BIGNUM* hash_num_recv = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_bin2bn(hash, 20, hash_num_have);
    BN_hex2bn(&exponent, exponent_file);
    BN_hex2bn(&public_key, public_key_file);
    BN_hex2bn(&signature_recv, signature_file);

    BN_mod_exp(hash_num_recv, signature_recv, exponent, public_key, ctx);

    if(BN_cmp(hash_num_have, hash_num_recv) == 0){
        printf("Podpis je validny!\n");
    }
    else{
        printf("Podpis nie je validny!\n");
    }

    free(file_contents);
    free(exponent_file);
    free(public_key_file);
    free(signature_file);
    BN_clear_free(hash_num_have);
    BN_clear_free(exponent);
    BN_clear_free(public_key);
    BN_clear_free(signature_recv);
    BN_clear_free(hash_num_recv);
    BN_CTX_free(ctx);

}

void sign_file(char* file_name){

    if(access("public.txt", F_OK) != 0 || access("private.txt", F_OK) != 0){
        printf("Kluce nenajdene, generujem nove kluce\n");
        generate_keys();
    }

    if(access(file_name, F_OK) != 0){
        printf("Subor nenajdeny, prerusujem program\n");
        return;
    }

    FILE* pub = fopen("public.txt", "r");
    FILE* pri = fopen("private.txt", "r");
    FILE* file = fopen(file_name, "r");
    FILE* sig = fopen("signature.txt", "w");

    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *file_contents = (unsigned char*)malloc(fsize);
    fread(file_contents, fsize, 1, file);
    fclose(file);

    unsigned char *hash = SHA1(file_contents, fsize, NULL);

    fseek(pri, 0, SEEK_END);
    long pri_key_size = ftell(pri);
    fseek(pri, 0, SEEK_SET);

    char *private_key_file = (char*)malloc(pri_key_size+1);
    fread(private_key_file, pri_key_size, 1, pri);
    fclose(pri);

    private_key_file[pri_key_size] = '\0';

    long pub_key_size = 0;
    char c;

    do{
        c = fgetc(pub);
        pub_key_size++;
    }
    while(c != '+');

    fseek(pub, 0, SEEK_SET);

    char* public_key_file = (char*)malloc(pub_key_size+1);

    fread(public_key_file, pub_key_size, 1, pub);
    fclose(pub);

    public_key_file[pub_key_size] = '\0';

    BIGNUM* hash_num = BN_new();
    BIGNUM* private_key = BN_new();
    BIGNUM* public_key = BN_new();
    BIGNUM* signature = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_bin2bn(hash, 20, hash_num);
    BN_hex2bn(&private_key, private_key_file);
    BN_hex2bn(&public_key, public_key_file);

    BN_mod_exp(signature, hash_num, private_key, public_key, ctx);

    BN_print_fp(sig, signature);

    fclose(sig);
    free(file_contents);
    free(private_key_file);
    free(public_key_file);
    BN_clear_free(hash_num);
    BN_clear_free(private_key);
    BN_clear_free(public_key);
    BN_clear_free(signature);
    BN_CTX_free(ctx);

    printf("Subor podpisany! Podpis je v signature.txt\n");

}

int main(int argc, char* argv[]){

    int c;

    if((c = getopt(argc, argv, "gs:v:")) != -1){
        switch(c){
            case 'g':
                generate_keys();
                break;
            case 's':
                sign_file(optarg);
                break;
            case 'v':
                validate_file(optarg);
                break;
            case '?':
                printf("Error v argumentoch. Spravne pouzitie je: \n");
                printf("\"./podpis -s {nazov suboru}\" - podpis suboru \n");
                printf("\"./podpis -v {nazov suboru}\" - validacia suboru \n");
                printf("\"./podpis -g\" - generacia klucov \n");
                break;
        }
    }
    else{
        printf("Argumenty neboli poskytnute. Spravne pouzitie je: \n");
        printf("\"./podpis -s {nazov suboru}\" - podpis suboru \n");
        printf("\"./podpis -v {nazov suboru}\" - validacia suboru \n");
        printf("\"./podpis -g\" - generacia klucov \n");
    }
    

    return EXIT_SUCCESS;
}