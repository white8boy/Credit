// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <string>
#include <sstream>
#include <iostream>

using namespace std;
using namespace seal;



void example_ckks_basics()
{   
    print_example_banner("Example: CKKS Basics");

    stringstream parms_stream;
    stringstream data_stream;
    stringstream sk_stream;
    stringstream pk_stream;
    stringstream galk_stream;
    /*
    In this example we demonstrate evaluating a polynomial function

        PI*x^3 + 0.4*x + 1

    on encrypted floating-point input data x for a set of 4096 equidistant points
    in the interval [0, 1]. This example demonstrates many of the main features
    of the CKKS scheme, but also the challenges in using it.

    We start by setting up the CKKS scheme.
    */
    {
    EncryptionParameters parms(scheme_type::ckks);

    /*
    We saw in `2_encoders.cpp' that multiplication in CKKS causes scales
    in ciphertexts to grow. The scale of any ciphertext must not get too close
    to the total size of coeff_modulus, or else the ciphertext simply runs out of
    room to store the scaled-up plaintext. The CKKS scheme provides a `rescale'
    functionality that can reduce the scale, and stabilize the scale expansion.

    Rescaling is a kind of modulus switch operation (recall `3_levels.cpp').
    As modulus switching, it removes the last of the primes from coeff_modulus,
    but as a side-effect it scales down the ciphertext by the removed prime.
    Usually we want to have perfect control over how the scales are changed,
    which is why for the CKKS scheme it is more common to use carefully selected
    primes for the coeff_modulus.

    More precisely, suppose that the scale in a CKKS ciphertext is S, and the
    last prime in the current coeff_modulus (for the ciphertext) is P. Rescaling
    to the next level changes the scale to S/P, and removes the prime P from the
    coeff_modulus, as usual in modulus switching. The number of primes limits
    how many rescalings can be done, and thus limits the multiplicative depth of
    the computation.

    It is possible to choose the initial scale freely. One good strategy can be
    to is to set the initial scale S and primes P_i in the coeff_modulus to be
    very close to each other. If ciphertexts have scale S before multiplication,
    they have scale S^2 after multiplication, and S^2/P_i after rescaling. If all
    P_i are close to S, then S^2/P_i is close to S again. This way we stabilize the
    scales to be close to S throughout the computation. Generally, for a circuit
    of depth D, we need to rescale D times, i.e., we need to be able to remove D
    primes from the coefficient modulus. Once we have only one prime left in the
    coeff_modulus, the remaining prime must be larger than S by a few bits to
    preserve the pre-decimal-point value of the plaintext.

    Therefore, a generally good strategy is to choose parameters for the CKKS
    scheme as follows:

        (1) Choose a 60-bit prime as the first prime in coeff_modulus. This will
                    give the highest precision when decrypting;
        (2) Choose another 60-bit prime as the last element of coeff_modulus, as
            this will be used as the special prime and should be as large as the
            largest of the other primes;
        (3) Choose the intermediate primes to be close to each other.

    We use CoeffModulus::Create to generate primes of the appropriate size. Note
    that our coeff_modulus is 200 bits total, which is below the bound for our
    poly_modulus_degree: CoeffModulus::MaxBitCount(8192) returns 218.   16384,438;
    */
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {47,31,31,31,31,47}));

    //参数放入parms.dat文件中
    auto size = parms.save(parms_stream, compr_mode_type::zstd);
    fstream file("parms.dat", ios::binary | ios::out);
    file << parms_stream.rdbuf();
    file.close();

    /*
    The return value of this function is the actual byte count of data written
    to the stream.
    */
    print_line(__LINE__);
    cout << "EncryptionParameters: wrote " << size << " bytes" << endl;

    /*
    We choose the initial scale to be 2^40. At the last level, this leaves us
    60-40=20 bits of precision before the decimal point, and enough (roughly
    10-20 bits) of precision after the decimal point. Since our intermediate
    primes are 40 bits (in fact, they are very close to 2^40), we can achieve
    scale stabilization as described above.
    */
    double scale = pow(2.0, 31);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    Serializable<PublicKey> public_key = keygen.create_public_key();
    //RelinKeys relin_keys;
    //keygen.create_relin_keys(relin_keys);
    //GaloisKeys gal_keys;
    //keygen.create_galois_keys(gal_keys);

    secret_key.save(sk_stream);
    public_key.save(pk_stream);

    fstream file1("pk.dat", ios::binary | ios::out);
    file1 << pk_stream.rdbuf();
    file1.close();

    Serializable<RelinKeys> relin_keys = keygen.create_relin_keys();
    auto size_rlk = relin_keys.save(data_stream);
    print_line(__LINE__);
    cout << "Serializable<RelinKeys>: wrote " << size_rlk << " bytes" << endl;

    pk_stream.seekp(0, pk_stream.beg);
    pk_stream.seekg(0, pk_stream.beg);
    PublicKey pk;
    pk.load(context,pk_stream);

    pk_stream.seekp(0, pk_stream.beg);
    pk_stream.seekg(0, pk_stream.beg);

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    cout << "Input vector: " << endl;
    
    /*
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
    that encodes the given floating-point value to every slot in the vector.
    */

    Plaintext x1_plain;
    Plaintext x2_plain;
    Plaintext x3_plain;
    Plaintext x4_plain;
    Plaintext x5_plain;
    Plaintext x6_plain;
    Plaintext x7_plain;
    Plaintext x8_plain;
    Plaintext x9_plain;
    Plaintext x10_plain;
    Plaintext x11_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(31759909.39, scale, x1_plain);
    encoder.encode(1357,        scale, x2_plain);
    encoder.encode(23404.50213, scale, x3_plain);
    encoder.encode(2649544.517, scale, x4_plain);
    encoder.encode(1454028.067, scale, x5_plain);
    encoder.encode(35383.92,    scale, x6_plain);
    encoder.encode(1562903.61,  scale, x7_plain);
    encoder.encode(1080870.105, scale, x8_plain);
    encoder.encode(0,           scale, x9_plain);
    encoder.encode(0.500545102, scale, x10_plain);
    encoder.encode(15019.15417, scale, x11_plain);

    encryptor.set_secret_key(secret_key);
    auto size_sym_encrypted1 = encryptor.encrypt_symmetric(x1_plain).save(data_stream);
    auto size_sym_encrypted2 = encryptor.encrypt_symmetric(x2_plain).save(data_stream);
    auto size_sym_encrypted3 = encryptor.encrypt_symmetric(x3_plain).save(data_stream);
    auto size_sym_encrypted4 = encryptor.encrypt_symmetric(x4_plain).save(data_stream);
    auto size_sym_encrypted5 = encryptor.encrypt_symmetric(x5_plain).save(data_stream);
    auto size_sym_encrypted6 = encryptor.encrypt_symmetric(x6_plain).save(data_stream);
    auto size_sym_encrypted7 = encryptor.encrypt_symmetric(x7_plain).save(data_stream);
    auto size_sym_encrypted8 = encryptor.encrypt_symmetric(x8_plain).save(data_stream);
    auto size_sym_encrypted9 = encryptor.encrypt_symmetric(x9_plain).save(data_stream);
    auto size_sym_encrypted10 = encryptor.encrypt_symmetric(x10_plain).save(data_stream);
    auto size_sym_encrypted11 = encryptor.encrypt_symmetric(x11_plain).save(data_stream);
 
    fstream file2("encryptdata.dat", ios::binary | ios::out);
    file2 << data_stream.rdbuf();
    file2.close();

    }
    
    //  now is server.
    
    {
    ifstream file("parms.dat");
    stringstream parmsout;
    parmsout << file.rdbuf();
    file.close();

    EncryptionParameters parms;
    parms.load(parmsout);
    parmsout.seekg(0, parmsout.beg);
    SEALContext context(parms);

    ifstream file1("pk.dat");
    stringstream pkout;
    pkout << file1.rdbuf();
    file1.close();

    PublicKey public_key;
    public_key.load(context,pkout);

    Evaluator evaluator(context);
    Encryptor encryptor(context, public_key);
    CKKSEncoder encoder(context);
    double scale=pow(2.0,31);

    ifstream file2("encryptdata.dat");
    stringstream dataout;
    dataout << file2.rdbuf();
    file2.close();

    RelinKeys rlk;
    Ciphertext x1_encrypted;
    Ciphertext x2_encrypted;
    Ciphertext x3_encrypted;
    Ciphertext x4_encrypted;
    Ciphertext x5_encrypted;
    Ciphertext x6_encrypted;
    Ciphertext x7_encrypted;
    Ciphertext x8_encrypted;
    Ciphertext x9_encrypted;
    Ciphertext x10_encrypted;
    Ciphertext x11_encrypted;

    rlk.load(context, dataout);
    x1_encrypted.load(context,dataout);
    x2_encrypted.load(context,dataout);
    x3_encrypted.load(context,dataout);
    x4_encrypted.load(context,dataout);
    x5_encrypted.load(context,dataout);
    x6_encrypted.load(context,dataout);
    x7_encrypted.load(context,dataout);
    x8_encrypted.load(context,dataout);
    x9_encrypted.load(context,dataout);
    x10_encrypted.load(context,dataout);
    x11_encrypted.load(context,dataout);

    vector<double> weight;
    weight.reserve(72);
    weight={0.784,0.371,-0.015,-0.023,-0.003,0.026,0.715,0.146,0.001,-0.106,0.001,0.001,0.630,-0.297,0.048,0.247,0.034,-0.008,-0.026,0.822,0.112,-0.030,-0.062,0.003,0.506,0.723,0.014,0.187,0.105,0.090,0.392,0.599,0.096,0.397,0.381,0.006,0.016,0.008,0.912,0.010,0.010,-0.013,0.010,0.132,0.902,-0.010,-0.004,-0.013,-0.006,0.085,-0.014,0.939,-0.020,-0.023,0.001,0.020,-0.004,-0.018,0.979,-0.030,0.017,0.039,-0.024,-0.023,-0.030,0.997};
    Plaintext plain_weight[6][11];
    for(int i=0;i<6;++i){
        encoder.encode(weight[i],   scale, plain_weight[i][5]);
        encoder.encode(weight[i+6], scale, plain_weight[i][4]);
        encoder.encode(weight[i+12],scale, plain_weight[i][2]);
        encoder.encode(weight[i+18],scale, plain_weight[i][1]);
        encoder.encode(weight[i+24],scale, plain_weight[i][3]);
        encoder.encode(weight[i+30],scale, plain_weight[i][0]);
        encoder.encode(weight[i+36],scale, plain_weight[i][6]);
        encoder.encode(weight[i+42],scale, plain_weight[i][8]);
        encoder.encode(weight[i+48],scale, plain_weight[i][7]);
        encoder.encode(weight[i+54],scale, plain_weight[i][10]);
        encoder.encode(weight[i+60],scale, plain_weight[i][9]);
    }
    
    Ciphertext encrypted_fw[6][11];
    int i,j;
    for(i=0;i<6;++i){
        evaluator.multiply_plain(x1_encrypted,plain_weight[i][0],encrypted_fw[i][0]);
        evaluator.multiply_plain(x2_encrypted,plain_weight[i][1],encrypted_fw[i][1]);
        evaluator.multiply_plain(x3_encrypted,plain_weight[i][2],encrypted_fw[i][2]);
        evaluator.multiply_plain(x4_encrypted,plain_weight[i][3],encrypted_fw[i][3]);
        evaluator.multiply_plain(x5_encrypted,plain_weight[i][4],encrypted_fw[i][4]);
        evaluator.multiply_plain(x6_encrypted,plain_weight[i][5],encrypted_fw[i][5]);
        evaluator.multiply_plain(x7_encrypted,plain_weight[i][6],encrypted_fw[i][6]);
        evaluator.multiply_plain(x8_encrypted,plain_weight[i][7],encrypted_fw[i][7]);
        evaluator.multiply_plain(x9_encrypted,plain_weight[i][8],encrypted_fw[i][8]);
        evaluator.multiply_plain(x10_encrypted,plain_weight[i][9],encrypted_fw[i][9]);
        evaluator.multiply_plain(x11_encrypted,plain_weight[i][10],encrypted_fw[i][10]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][0]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][1]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][2]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][3]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][4]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][5]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][6]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][7]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][8]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][9]);
        evaluator.rescale_to_next_inplace(encrypted_fw[i][10]);
    }

    for(i=1;i<11;i++){
        for(int j=0;j<6;j++){
            evaluator.add_inplace(encrypted_fw[j][0],encrypted_fw[j][i]);
        }
    }

    Ciphertext encrypted_fv;
    evaluator.add(encrypted_fw[0][0],encrypted_fw[1][0],encrypted_fv);
    evaluator.add_inplace(encrypted_fv,encrypted_fw[2][0]);
    evaluator.add_inplace(encrypted_fv,encrypted_fw[3][0]);
    evaluator.add_inplace(encrypted_fv,encrypted_fw[4][0]);
    evaluator.add_inplace(encrypted_fv,encrypted_fw[5][0]);
    
    double six=0.16666667;
    Plaintext plain_six;
    encoder.encode(six,scale,plain_six);
    parms_id_type last_parms_id = encrypted_fv.parms_id();
    evaluator.mod_switch_to_inplace(plain_six,last_parms_id);
    evaluator.multiply_plain_inplace(encrypted_fv,plain_six);
    evaluator.rescale_to_next_inplace(encrypted_fv);

    for(j=0;j<6;j++){
        last_parms_id = encrypted_fv.parms_id();
        evaluator.mod_switch_to_inplace(encrypted_fw[j][0],last_parms_id);
        encrypted_fv.scale()=pow(2.0,31);
        encrypted_fw[j][0].scale()=pow(2.0,31);
        evaluator.sub_inplace(encrypted_fw[j][0],encrypted_fv);
    }

    vector<double> fweight;
    fweight.reserve(6);
    fweight={0.001376,0.000851,0.071265,0.014455,0.000682,0.911371};

    Plaintext f_six[6];
    Ciphertext f_result[6];

    for(j=0;j<6;j++){
        encoder.encode(fweight[j],scale,f_six[j]);
        last_parms_id = encrypted_fw[j][0].parms_id();
        evaluator.mod_switch_to_inplace(f_six[j],last_parms_id);
        evaluator.multiply_plain(encrypted_fw[j][0],f_six[j],f_result[j]);
        evaluator.rescale_to_next_inplace(f_result[j]);
    }

    stringstream result_stream;
    auto size_encrypted_prod = encrypted_fw[0][0].save(result_stream);
    print_line(__LINE__);
    cout << "Ciphertext (secret-key): wrote " << size_encrypted_prod << " bytes" << endl;
    
    Ciphertext encrypted_f1;

    evaluator.add(f_result[0],f_result[1],encrypted_f1);
    evaluator.add_inplace(encrypted_f1,f_result[2]);
    evaluator.add_inplace(encrypted_f1,f_result[3]);
    evaluator.add_inplace(encrypted_f1,f_result[4]);
    evaluator.add_inplace(encrypted_f1,f_result[5]);

    for(j=0;j<6;j++){
        evaluator.square_inplace(encrypted_fw[j][0]);
        evaluator.relinearize_inplace(encrypted_fw[j][0], rlk);
        evaluator.rescale_to_next_inplace(encrypted_fw[j][0]);
    }

    Ciphertext encrypted_f2;

    evaluator.add(encrypted_fw[0][0],encrypted_fw[1][0],encrypted_f2);
    evaluator.add_inplace(encrypted_f2,encrypted_fw[2][0]);
    evaluator.add_inplace(encrypted_f2,encrypted_fw[3][0]);
    evaluator.add_inplace(encrypted_f2,encrypted_fw[4][0]);
    evaluator.add_inplace(encrypted_f2,encrypted_fw[5][0]);

    //stringstream result_stream;
    //auto size_encrypted_prod = encrypted_f1.save(result_stream);
    //print_line(__LINE__);
    //cout << "Ciphertext (secret-key): wrote " << size_encrypted_prod << " bytes" << endl;
    size_encrypted_prod = encrypted_fw[0][0].save(result_stream);
    print_line(__LINE__);
    cout << "Ciphertext (secret-key): wrote " << size_encrypted_prod << " bytes" << endl;
    
    fstream file3("resultdata.dat", ios::binary | ios::out);
    file3 << result_stream.rdbuf();
    file3.close();

    }
    
    //client again;

    {
    //cout << "are you ok?" << endl;

    ifstream file1("parms.dat");
    stringstream parmsout;
    parmsout << file1.rdbuf();
    file1.close();

    EncryptionParameters parms;
    parms.load(parmsout);
    parmsout.seekg(0, parmsout.beg);
    SEALContext context(parms);

    //cout << "are you ok?" << endl;

    SecretKey sk;
    sk.load(context, sk_stream);
    Decryptor decryptor(context, sk);
    CKKSEncoder encoder(context);

    ifstream file("resultdata.dat");
    stringstream dataout;
    dataout << file.rdbuf();
    file.close();

    Ciphertext encrypted_f1;
    Ciphertext encrypted_f2;
    encrypted_f1.load(context, dataout); 
    encrypted_f2.load(context, dataout);

    Plaintext plain_result;
    /*
    Decrypt, decode, and print the result.
    */
    decryptor.decrypt(encrypted_f1, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << " f1" << endl;
    print_vector(result, 2, 10);

    decryptor.decrypt(encrypted_f2, plain_result);
    encoder.decode(plain_result, result);
    cout << " f2^2" << endl;
    print_vector(result, 2, 10);
    
    
    }
    /*
    While we did not show any computations on complex numbers in these examples,
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications of complex numbers behave just as one would expect.
    */
}
