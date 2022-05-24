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
    Serializable<GaloisKeys> gal_keys = keygen.create_galois_keys();
    //RelinKeys relin_keys;
    //keygen.create_relin_keys(relin_keys);
    //GaloisKeys gal_keys;
    //keygen.create_galois_keys(gal_keys);

    secret_key.save(sk_stream);
    public_key.save(pk_stream);
    gal_keys.save(pk_stream);

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

    vector<double> input;
    input.reserve(72);
    input.resize(72);
    for (int i = 0; i < 6; i++)
    {
        input[i+30]=31759909.39;
        
        input[i+18]=1357;
        
        input[i+12]=23404.50213;
        
        input[i+24]=2649544.517;
        
        input[i+6]=1454028.067;
        
        input[i]=35383.92;
        
        input[i+36]=1562903.61;
        
        input[i+48]=1080870.105;
        
        input[i+42]=0.0;
        
        input[i+60]=0.500545102;
        
        input[i+54]=15019.15417;
        
        input[i+66]=0.0;
    }

    cout << "Input vector: " << endl;
    
    /*
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
    that encodes the given floating-point value to every slot in the vector.
    */

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);

    encryptor.set_secret_key(secret_key);
    auto size_sym_encrypted2 = encryptor.encrypt_symmetric(x_plain).save(data_stream);

//    encryptor.encrypt(x_plain, x_encrypted);   
    Ciphertext fxx_encrypted;

    print_line(__LINE__);
        cout << "Serializable<Ciphertext> (seeded secret-key): wrote " << size_sym_encrypted2 << " bytes" << endl;
    
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
    GaloisKeys gal_keys;
    public_key.load(context,pkout);
    gal_keys.load(context,pkout);

    Evaluator evaluator(context);
    Encryptor encryptor(context, public_key);
    CKKSEncoder encoder(context);
    double scale=pow(2.0,31);

    ifstream file2("encryptdata.dat");
    stringstream dataout;
    dataout << file2.rdbuf();
    file2.close();

    RelinKeys rlk;
    Ciphertext fxx_encrypted;
    Ciphertext x_encrypted;

    rlk.load(context, dataout);
    x_encrypted.load(context,dataout);

    vector<double> weight;
    weight.reserve(72);
    weight={0.784,0.371,-0.015,-0.023,-0.003,0.026,0.715,0.146,0.001,-0.106,0.001,0.001,0.630,-0.297,0.048,0.247,0.034,-0.008,-0.026,0.822,0.112,-0.030,-0.062,0.003,0.506,0.723,0.014,0.187,0.105,0.090,0.392,0.599,0.096,0.397,0.381,0.006,0.016,0.008,0.912,0.010,0.010,-0.013,0.010,0.132,0.902,-0.010,-0.004,-0.013,-0.006,0.085,-0.014,0.939,-0.020,-0.023,0.001,0.020,-0.004,-0.018,0.979,-0.030,0.017,0.039,-0.024,-0.023,-0.030,0.997,0,0,0,0,0,0};
    Plaintext plain_weight;
    encoder.encode(weight, scale, plain_weight);

    evaluator.multiply_plain(x_encrypted, plain_weight, fxx_encrypted);
    evaluator.rescale_to_next_inplace(fxx_encrypted);
  
    //cout << "    + Scale of x^2 before rescale: " << log2(fxx_encrypted.scale()) << " bits" << endl;
    //cout << "are you ok?" << endl;
    /*
    重复输入和参数相乘，获得全部结果值。
    */
    Ciphertext fxx6_encrypted;
    evaluator.rotate_vector(fxx_encrypted, 6, gal_keys, fxx6_encrypted);
    evaluator.add_inplace(fxx_encrypted,fxx6_encrypted);
    evaluator.rotate_vector(fxx_encrypted, 12, gal_keys, fxx6_encrypted);
    evaluator.add_inplace(fxx_encrypted,fxx6_encrypted);
    evaluator.rotate_vector(fxx_encrypted, 24, gal_keys, fxx6_encrypted);
    evaluator.add_inplace(fxx_encrypted,fxx6_encrypted);
    evaluator.rotate_vector_inplace(fxx6_encrypted, 24, gal_keys);
    evaluator.add_inplace(fxx_encrypted,fxx6_encrypted);
    //cout << "are you ok?" << endl;
  //  cout << "    + Scale of x^2 before rescale: " << log2(fxx_encrypted.scale()) << " bits" << endl;
      
    /*
    First print the true result.
    计算出原始的6个F指标，下一步旋转求均值。
    */

    evaluator.rotate_vector(fxx_encrypted, -1, gal_keys, fxx6_encrypted);
    evaluator.add_inplace(fxx_encrypted,fxx6_encrypted);
    evaluator.rotate_vector_inplace(fxx6_encrypted, -1, gal_keys);
    evaluator.add_inplace(fxx_encrypted,fxx6_encrypted);
    evaluator.rotate_vector_inplace(fxx6_encrypted, -1, gal_keys);
    evaluator.add_inplace(fxx_encrypted,fxx6_encrypted);
    evaluator.rotate_vector_inplace(fxx6_encrypted, -1, gal_keys);
    evaluator.add_inplace(fxx_encrypted,fxx6_encrypted);
    evaluator.rotate_vector_inplace(fxx6_encrypted, -1, gal_keys);
    evaluator.add_inplace(fxx_encrypted,fxx6_encrypted);

    vector<double> six;
    six.reserve(72);
    six={0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667,0.1666666667};
    Plaintext six_plain;
    encoder.encode(six, scale, six_plain);
    Ciphertext encrypted_avaerge;
    print_line(__LINE__);
    cout << "first div six to get avaerge" << endl;
    parms_id_type last_parms_id = fxx_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(six_plain, last_parms_id);

    evaluator.multiply_plain_inplace(fxx_encrypted, six_plain);
    //last_parms_id = encrypted_avaerge.parms_id();
    evaluator.rescale_to_next(fxx_encrypted, encrypted_avaerge);
    evaluator.rotate_vector_inplace(fxx6_encrypted, 5, gal_keys);

    /*
    获得均值之后，全部相减，获得均值差。
    */
    Ciphertext encrypted_avacha;
    last_parms_id = encrypted_avaerge.parms_id();
    evaluator.mod_switch_to_inplace(fxx6_encrypted, last_parms_id);
    fxx6_encrypted.scale()= pow(2.0,31);
    encrypted_avaerge.scale()= pow(2.0,31);
    evaluator.sub_inplace(fxx6_encrypted,encrypted_avaerge);
    //cout << "are you ok?" << endl;

    /*
    对均值差分两步处理，1.乘以权重再求和。2.平方之后再求和。
    */
    /*
    1.乘以权重再求和。
    */
    vector<double> weight2;
    weight2.reserve(72);
    weight2={0.001376,0.000851,0.071265,0.014455,0.000682,0.911371,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    Plaintext weight2_plain;
    encoder.encode(weight2, scale, weight2_plain);
    Ciphertext encrypted_f1;
    last_parms_id = fxx6_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(weight2_plain, last_parms_id);
    evaluator.multiply_plain(fxx6_encrypted, weight2_plain,encrypted_f1);
    evaluator.rescale_to_next_inplace(encrypted_f1);

    evaluator.rotate_vector(encrypted_f1, 1, gal_keys, fxx_encrypted);
    evaluator.add_inplace(encrypted_f1,fxx_encrypted);
    evaluator.rotate_vector_inplace(fxx_encrypted, 1, gal_keys);
    evaluator.add_inplace(encrypted_f1,fxx_encrypted);
    evaluator.rotate_vector_inplace(fxx_encrypted, 1, gal_keys);
    evaluator.add_inplace(encrypted_f1,fxx_encrypted);
    evaluator.rotate_vector_inplace(fxx_encrypted, 1, gal_keys);
    evaluator.add_inplace(encrypted_f1,fxx_encrypted);
    evaluator.rotate_vector_inplace(fxx_encrypted, 1, gal_keys);
    evaluator.add_inplace(encrypted_f1,fxx_encrypted);

    /*
    2.平方之后再求和。
    */
    stringstream result_stream;
    auto size_encrypted_prod = fxx6_encrypted.save(result_stream);
    print_line(__LINE__);
    
    Ciphertext encrypted_f2;

    evaluator.square(fxx6_encrypted,encrypted_f2);
    evaluator.relinearize_inplace(encrypted_f2,rlk);
    evaluator.rescale_to_next_inplace(encrypted_f2);
   
    evaluator.rotate_vector(encrypted_f2, 1, gal_keys, fxx_encrypted);
    evaluator.add_inplace(encrypted_f2,fxx_encrypted);
    evaluator.rotate_vector_inplace(fxx_encrypted, 1, gal_keys);
    evaluator.add_inplace(encrypted_f2,fxx_encrypted);
    evaluator.rotate_vector_inplace(fxx_encrypted, 1, gal_keys);
    evaluator.add_inplace(encrypted_f2,fxx_encrypted);
    evaluator.rotate_vector_inplace(fxx_encrypted, 1, gal_keys);
    evaluator.add_inplace(encrypted_f2,fxx_encrypted);
    evaluator.rotate_vector_inplace(fxx_encrypted, 1, gal_keys);
    evaluator.add_inplace(encrypted_f2,fxx_encrypted);
    
    cout << "second div six to get f2" << endl;

    /*
    //encoder.encode(six, scale, six_plain);    
    last_parms_id = encrypted_f2.parms_id();
    evaluator.mod_switch_to_inplace(six_plain, last_parms_id);
    evaluator.multiply_plain_inplace(encrypted_f2, six_plain);
    evaluator.rescale_to_next_inplace(encrypted_f2);
    */

    
    cout << "Ciphertext (secret-key): wrote " << size_encrypted_prod << " bytes" << endl;
    size_encrypted_prod = fxx_encrypted.save(result_stream);
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

    cout << "are you ok?" << endl;

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
    print_vector(result, 6, 10);

    decryptor.decrypt(encrypted_f2, plain_result);
    encoder.decode(plain_result, result);
    cout << " f2^2" << endl;
    print_vector(result, 6, 10);
    
    
    }
    /*
    While we did not show any computations on complex numbers in these examples,
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications of complex numbers behave just as one would expect.
    */
}
