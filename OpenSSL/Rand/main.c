#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <ctype.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    unsigned char *rand1 = "63-3b-6d-07-65-1a-09-31-7a-4f-b4-aa-ef-3f-7a-55-d0-33-93-52-1e-81-fb-63-11-26-ed-9e-8e-a7-10-f6-63-9d-eb-92-90-eb-76-0b-90-5a-eb-b4-75-d3-a1-cf-d2-91-39-c1-89-32-84-22-12-4e-77-57-4d-25-85-98";
    unsigned char *rand2 = "92-05-d8-b5-fa-85-97-b6-22-f4-bd-26-11-cf-79-8c-db-4a-28-27-bb-d3-31-56-74-16-df-cb-f5-61-a7-9d-18-c2-63-92-f1-cb-c3-6d-2b-77-19-aa-21-07-8e-fe-8b-1a-4f-7d-70-6e-a4-7b-c8-68-30-43-12-50-30-1e";
    unsigned char OR[191];
    for(int i=0; i<191;i=i+3){
        printf("[i]%c %c \n",rand1[i], rand2[i]);
        int val1 = (isdigit(rand1[i]) ? rand1[i] - '0' : 10 + (tolower(rand1[i]) - 'a'));
        int val2 = (isdigit(rand2[i]) ? rand2[i] - '0' : 10 + (tolower(rand2[i]) - 'a'));
        OR[i] = val1 | val2;
        printf("%x \n\n", OR[i]);
        printf("[i+1]%c %c \n",rand1[i+1], rand2[i+1]);
        val1 = (isdigit(rand1[i+1]) ? rand1[i+1] - '0' : 10 + (tolower(rand1[i+1]) - 'a'));
        val2 = (isdigit(rand2[i+1]) ? rand2[i+1] - '0' : 10 + (tolower(rand2[i+1]) - 'a'));
        OR[i+1] = val1 | val2;
        printf("%x \n\n", OR[i+1]);
        OR[i+2] = rand1[i+2];
        printf("%c\n\n", OR[i+2]);
    }

    for(int i =0; i <191; i++)
        if (OR[i]!=rand1[2])
            printf("%x",OR[i]);
        else printf("%c",OR[i]);

    unsigned char *k1 = "f3-3f-fd-b7-ff-9f-9f-b7-7a-ff-bd-ae-ff-ff-7b-dd-db-7b-bb-77-bf-d3-fb-77-75-36-ff-df-ff-e7-b7-ff-7b-df-eb-92-f1-eb-f7-6f-bb-7f-fb-be-75-d7-af-ff-db-9b-7f-fd-f9-7e-a4-7b-da-6e-77-57-5f-75-b5-9e";
    unsigned char AND[191];
    for(int i=0; i<191;i=i+3){
        printf("[i]%c %c \n",rand1[i], rand2[i]);
        int val1 = (isdigit(rand1[i]) ? rand1[i] - '0' : 10 + (tolower(rand1[i]) - 'a'));
        int val2 = (isdigit(rand2[i]) ? rand2[i] - '0' : 10 + (tolower(rand2[i]) - 'a'));
        AND[i] = val1 & val2;
        printf("%x \n\n", AND[i]);
        printf("[i+1]%c %c \n",rand1[i+1], rand2[i+1]);
        val1 = (isdigit(rand1[i+1]) ? rand1[i+1] - '0' : 10 + (tolower(rand1[i+1]) - 'a'));
        val2 = (isdigit(rand2[i+1]) ? rand2[i+1] - '0' : 10 + (tolower(rand2[i+1]) - 'a'));
        AND[i+1] = val1 & val2;
        printf("%x \n\n", AND[i+1]);
        AND[i+2] = rand1[i+2];
        printf("%c\n\n", AND[i+2]);
    }
    for(int i =0; i <191; i++)
        if (AND[i]!=rand1[2])
            printf("%x",AND[i]);
        else printf("%c",AND[i]);


    unsigned char *k2 = "02-01-48-05-60-00-01-30-22-44-b4-22-01-0f-78-04-d0-02-00-02-1a-81-31-42-10-06-cd-8a-84-21-00-94-00-80-63-92-90-cb-42-09-00-52-09-a0-21-03-80-ce-82-10-09-41-00-22-84-22-00-48-30-43-00-00-00-18";
    unsigned char XOR[191];
    for(int i=0; i<191;i=i+3){
        printf("[i]%c %c \n",k1[i], k2[i]);
        int val1 = (isdigit(k1[i]) ? k1[i] - '0' : 10 + (tolower(k1[i]) - 'a'));
        int val2 = (isdigit(k2[i]) ? k2[i] - '0' : 10 + (tolower(k2[i]) - 'a'));
        XOR[i] = val1 ^ val2;
        printf("%x \n\n", XOR[i]);
        printf("[i+1]%c %c \n",k1[i+1], k2[i+1]);
        val1 = (isdigit(k1[i+1]) ? k1[i+1] - '0' : 10 + (tolower(k1[i+1]) - 'a'));
        val2 = (isdigit(k2[i+1]) ? k2[i+1] - '0' : 10 + (tolower(k2[i+1]) - 'a'));
        XOR[i+1] = val1 ^ val2;
        printf("%x \n\n", XOR[i+1]);
        XOR[i+2] = k1[i+2];
        printf("%c\n\n", XOR[i+2]);
    }
    for(int i =0; i <191; i++)
        if (XOR[i]!=rand1[2])
            printf("%x",XOR[i]);
        else printf("%c",XOR[i]);
    return 0;

}

#define MAX 128
/*int main() {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    unsigned char random_string[MAX];
    if (RAND_load_file("/dev/random",64)!=64)// seeding.
        handle_errors();
        //ERR_print_errors_fp(stderr);
        // fprintf(stderr,"Error with the initialization of the PRNG \n");

    if (RAND_bytes(random_string,MAX)!=1) //creating rand bytes and saving in random_string
        handle_errors();
        // fprintf(stderr,"Error with the generation \n");

    printf("Sequence generated: ");
    for(int i=0; i < MAX; i++)
        printf("%02x-",random_string[i]);
    printf("\n");



    ERR_free_strings();
    return 0;
}*/
