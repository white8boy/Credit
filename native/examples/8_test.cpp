// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <fstream>
#include <iostream>

using namespace std;
using namespace seal;

void sum(SEALContext context);
void avaerge(SEALContext context);
void paralle_mux(SEALContext context);
void cs_model();


int main()
{
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
    while (true)
    {
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| The following examples should be executed while reading |" << endl;
        cout << "| comments in associated files in native/examples/.       |" << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| Examples                                                |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;
        cout << "| 1. sum                                                  |" << endl;
        cout << "| 2. avaerge                                              |" << endl;
        cout << "| 3. paralle mux                                          |" << endl;
        cout << "| 4. cs_model                                             |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;

        /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
        size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
        cout << "[" << setw(7) << right << megabytes << " MB] "
             << "Total allocation from the memory pool" << endl;

        int selection = 0;
        bool valid = true;
        do
        {
            cout << endl << "> Run example (1 ~ 4) or exit (0): ";
            if (!(cin >> selection))
            {
                valid = false;
            }
            else if (selection < 0 || selection > 4)
            {
                valid = false;
            }
            else
            {
                valid = true;
            }
            if (!valid)
            {
                cout << "  [Beep~~] valid option: type 0 ~ 4" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!valid);


        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

        switch (selection)
        {
        case 1:
            sum(parms);
            break;

        case 2:
            avaerge(parms);
            break;

        case 3:
            paralle_mux(parms);
            break;

        case 4:
            cs_model();
            break;

        case 0:
            return 0;
        }
    }

    return 0;
}

void sum(SEALContext context){
    chrono::high_resolution_clock::time_point time_start, time_end;

    auto &parms = context.first_context_data()->parms();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    vector<double> money={523.12,6547.14,564.52,893.14,1213.47,6356.26,5769.25,3465.05,214.90,363.56};
    double scale = pow(2.0,20);
    print_vector(money);
    time_start = chrono::high_resolution_clock::now();
    cout << "====" <<endl;
    Ciphertext encrypted1(context);
    Ciphertext encrypted2(context);
    Plaintext plain;
    ckks_encoder.encode(0,scale, plain);
    encryptor.encrypt(plain, encrypted1);
    for(int i=0;i<10;++i){
        ckks_encoder.encode(money[i],scale, plain);
        encryptor.encrypt(plain, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
    }

    decryptor.decrypt(encrypted1,plain);
    vector<double> result;
    ckks_encoder.decode(plain,result);
    print_vector(result);
    time_end = chrono::high_resolution_clock::now();
    chrono::microseconds time_add_sum(0);
    time_add_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    auto avg_add = time_add_sum.count();
    cout << "sum:" << avg_add << " microseconds" << endl;
}

void avaerge(SEALContext context){

    chrono::high_resolution_clock::time_point time_start, time_end;
    auto &parms = context.first_context_data()->parms();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    vector<double> money={523.12,6547.14,564.52,893.14,1213.47,6356.26,5769.25,3465.05,214.90,363.56};
    double scale = pow(2.0,30);
    print_vector(money);
    cout << "====" <<endl;

    time_start = chrono::high_resolution_clock::now();
    Ciphertext encrypted1(context);
    Ciphertext encrypted2(context);
    Plaintext plain;
    ckks_encoder.encode(0,scale, plain);
    encryptor.encrypt(plain, encrypted1);
    for(int i=0;i<10;++i){
        ckks_encoder.encode(money[i],scale, plain);
        encryptor.encrypt(plain, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
    }

    double test1=0.1;
    ckks_encoder.encode(test1,scale, plain);
    encryptor.encrypt(plain, encrypted2);
    evaluator.multiply_inplace(encrypted1, encrypted2);

    decryptor.decrypt(encrypted1,plain);
    vector<double> result;
    ckks_encoder.decode(plain,result);
    print_vector(result);
    time_end = chrono::high_resolution_clock::now();
    chrono::microseconds time_add_sum(0);
    time_add_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    auto avg_add = time_add_sum.count();
    cout << "Average: " << avg_add << " microseconds" << endl;

}

void paralle_mux(SEALContext context){
    chrono::high_resolution_clock::time_point time_start, time_end;

    auto &parms = context.first_context_data()->parms();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    vector<double> money={523.12,6547.14,564.52,893.14,1213.47,6356.26,5769.25,3465.05,214.90,363.56};
    vector<double> param={0.37,0.85,0.96,0.32,0.76,0.43,0.56,0.65,0.45,0.42};
    double scale = pow(2.0,30);
    print_vector(money);
    print_vector(param);
    cout << "====" <<endl;

    time_start = chrono::high_resolution_clock::now();
    Ciphertext encrypted1(context);
    Ciphertext encrypted2(context);
    Plaintext plain;
    ckks_encoder.encode(money,scale, plain);
    encryptor.encrypt(plain, encrypted1);
    ckks_encoder.encode(param,scale, plain);
    encryptor.encrypt(plain, encrypted2);

    evaluator.multiply_inplace(encrypted1, encrypted2);
    decryptor.decrypt(encrypted1,plain);
    vector<double> result;
    ckks_encoder.decode(plain,result);
    print_vector(result);
    time_end = chrono::high_resolution_clock::now();
    chrono::microseconds time_add_sum(0);
    time_add_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    auto avg_add = time_add_sum.count();
    cout << "param_mux: " << avg_add << " microseconds" << endl;
}

void cs_model(){

    cout << "client:create parms and key" <<endl;
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    SEALContext context(parms);

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    stringstream parms_stream;
    stringstream data1_stream;
    stringstream data2_stream;
    parms.save(parms_stream);
    
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    vector<double> money={523.12,6547.14,564.52,893.14,1213.47,6356.26,5769.25,3465.05,214.90,363.56};
    vector<double> param={0.37,0.85,0.96,0.32,0.76,0.43,0.56,0.65,0.45,0.42};
    double scale = pow(2.0,30);
    print_vector(money);
    print_vector(param);
    cout << "====" <<endl;

    Plaintext plain;
    ckks_encoder.encode(money,scale, plain);
    encryptor.encrypt(plain).save(data1_stream);
    ckks_encoder.encode(param,scale, plain);
    encryptor.encrypt(plain).save(data2_stream);

    cout << "client send the param and data" << endl;

    cout << "sever load the param and data" << endl;
    EncryptionParameters parms2;
    parms2.load(parms_stream);
    parms_stream.seekg(0, parms_stream.beg);
    SEALContext context2(parms2);
    stringstream data3_stream;
    Evaluator evaluator2(context2);
    Ciphertext encrypted12, encrypted22,encrypted_prod;
    encrypted12.load(context2, data1_stream);
    encrypted22.load(context2, data2_stream);
    evaluator.multiply(encrypted12, encrypted22,encrypted_prod);
    encrypted_prod.save(data3_stream);

    cout << "client accept the result" << endl;
    Ciphertext encrypted_result;
    encrypted_result.load(context, data3_stream);

    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    ckks_encoder.decode(plain_result, result);
    print_line(__LINE__);
    cout << "Result: " << endl;
    print_vector(result);
}