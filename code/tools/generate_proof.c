#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sep.h"
#include "osig.h"
#include "show.h"
#include "randombytes.h"
#include "random.h"

// This module simulates the Prover (Wallet)
// It loads the user's private credentials and transforms them into an anonymous
// Zero-Knowledge Proof (ZKP) using the Fiat-Shamir heuristic over Module-SIS/LWE.
// It strictly enforces Data Minimization: the original signature is blinded.


// AUXILIARY FUNCTIONS FOR DISK SERIALIZATION
// Multi-dimensional polynomials and matrices exist in RAM as complex dynamic FLINT structures. 
// These functions extract mathematical coefficients to binary.

/*
 * Saves a standard lattice polynomial (poly_q) to disk.
 * It iterates through all N coefficients (PARAM_N) and writes their 64-bit values.
 * This function is primarily used for saving public and private key elements.
 */
void save_poly(FILE *f, poly_q p) {
    for (size_t n = 0; n < PARAM_N; n++) {
        int64_t c = poly_q_get_coeff(p, n);
        fwrite(&c, sizeof(int64_t), 1, f);
    }
}

/*
 * Saves the proof polynomial (poly_qshow) to disk.
 * Zero-knowledge proofs (SHOW scheme) operate in an algebraically distinct field,
 * so this function uses its own parameter for the polynomial's degree (PARAM_N_SHOW).
 */
void save_poly_qshow(FILE *f, poly_qshow p) {
    for (size_t n = 0; n < PARAM_N_SHOW; n++) {
        int64_t c = poly_qshow_get_coeff(p, n);
        fwrite(&c, sizeof(int64_t), 1, f);
    }
}

/*
 * Serializes a complex matrix of ZKP polynomials (K x K).
 * Iterates over all rows and columns of the matrix. 
 * Access via the arrow operator (->) ensures correct dereferencing of dynamically allocated vectors within the FLINT library, 
 * Protection against memory access errors 
 */
void save_mat_k_k(FILE *f, poly_qshow_mat_k_k m) {
    for(size_t i=0; i<PARAM_K_SHOW; i++)
        for(size_t j=0; j<PARAM_K_SHOW; j++)
            save_poly_qshow(f, m[0].rows[i]->entries[j]); // Changed dot to arrow
}


//Interface mapped to the Python Backend Orchestrator.
int main(int argc, char *argv[]) {
    // The Prover expects 3 arguments:
    // 1. Attribute value to prove (e.g., 1 for "True")
    // 2. Path to the user's local encrypted wallet
    // 3. Output path for the generated anonymous ZKP binary
    if (argc != 4) {
        printf("{\"status\": \"error\", \"message\": \"Usage: ./generate_proof <value> <path_to_wallet> <output_proof.bin>\"}\n");
        return 1;
    }

    uint8_t expected_value = (uint8_t)atoi(argv[1]);
    char *wallet_path = argv[2];
    char *proof_path = argv[3];

    // Initialize the algebraic backend (FLINT) and secure randomness
    arith_setup();
    random_init();

    // Variables for performance benchmarking
    struct timespec start, end;
    double time_prove_ms = 0.0;
    double time_embed_ms = 0.0;
    double time_prove_fs_ms = 0.0;
    double time_io_ms = 0.0;

    //verifying one own signature on the message m with value 1 (blind signature)
    // Encode the requested attribute into the message buffer
    uint8_t msg[PARAM_M*PARAM_N/8];
    memset(msg, 0, sizeof(msg));
    msg[0] = expected_value;

    sep_sk_t dummy_sk; //Auxiliary variable required for initialization routines
    sep_pk_t pk; // Authority's Public Key
    user_sk_t usk; // User Secret Key 
    user_pk_t upk; // User Public Key
    sep_sig_t sig; // The original blind signature from the Authority
    show_proof_t proof; // The final Zero-Knowledge Proof structure 	

    // Allocate dynamic lattice structures in FLINT
    sep_keys_init(&pk, &dummy_sk); user_keys_init(&upk, &usk);
    sep_sig_init(&sig); show_proof_init(&proof);

    //PHASE 1: I/O LOAD TIME
    // Measure the overhead of loading massive lattice keys from storage to RAM.
    clock_gettime(CLOCK_MONOTONIC, &start);

    // LOADING THE AUTHORITY'S PUBLIC KEY
    FILE *fpk = fopen("/home/lac/_build/public_key.bin", "rb"); //The path to public keys
    if(!fpk) { //Check if the file exists
       printf("{\"status\": \"error\", \"message\": \"Public key not found public_key.bin\"}\n"); 
       return 1; 
    } 
    
    // Read the master seed safely
    if(fread(pk.seed, 1, SEED_BYTES, fpk) != SEED_BYTES) { fclose(fpk); return 1; }
    
    // Deserialize the huge lattice matrix B
    // The loop reads linear data from a file and constructs a multidimensional structure of polynomials in RAM.
    for (size_t k = 0; k < PARAM_K; k++) {
        for (size_t i = 0; i < PARAM_D; i++) {
            for (size_t j = 0; j < PARAM_D; j++) {
                int64_t c; 
                for(size_t n=0; n<PARAM_N; n++){ 
                    // Reading a 64-bit coefficient from a file (BEZPEČNÉ NAČÍTÁNÍ)
                    if(fread(&c, sizeof(int64_t), 1, fpk) != 1) { fclose(fpk); return 1; }
                    // Store the coefficient at the correct location in dynamic memory
                    poly_q_set_coeff(pk.B[k]->rows[i]->entries[j], n, c); 
                }
            }
        }
    }
    fclose(fpk);

    //Load the User's Wallet
    // Prover opens an encrypted file generated by the Authority
    // The secret key (usk) and the original signature (sig) are loaded only into the program’s temporary memory and will not be sent to the Verifier.
    // They will serve only as input for the ZKP transformation.
    // Check if the wallet exists and open it
    FILE *fw = fopen(wallet_path, "rb");
    if(!fw) { 
        printf("{\"status\": \"error\", \"message\": \"Wallet not found\"}\n"); return 1; 
    }

    // Load User Public Key
    for (size_t i = 0; i < PARAM_D; i++) { 
        int64_t c; 
        for(size_t n=0; n<PARAM_N; n++){ 
            if(fread(&c, sizeof(int64_t), 1, fw) != 1) { fclose(fw); return 1; }
            poly_q_set_coeff(upk.t->entries[i], n, c); 
        } 
    }

    if(fread(upk.seed, 1, SEED_BYTES, fw) != SEED_BYTES) { fclose(fw); return 1; }
    
    // Load User Secret Key
    for(int s=0; s<2; s++) {
        for (size_t i = 0; i < PARAM_D; i++) { 
            int64_t c; 
            for(size_t n=0; n<PARAM_N; n++){ 
                if(fread(&c, sizeof(int64_t), 1, fw) != 1) { fclose(fw); return 1; }
                poly_q_set_coeff(usk.s[s]->entries[i], n, c); 
            } 
        }
    }
    // Load the Authority's Signature components
    // It consists of several lattice polynomials (tag, v12, v2, v3)
    { 
        int64_t c; 
        for(size_t n=0; n<PARAM_N; n++){ 
            if(fread(&c, sizeof(int64_t), 1, fw) != 1) { fclose(fw); return 1; }
            poly_q_set_coeff(sig.tag, n, c); 
        } 
    }
    for (size_t i = 0; i < PARAM_D; i++) { 
        int64_t c; 
        for(size_t n=0; n<PARAM_N; n++){ 
            if(fread(&c, sizeof(int64_t), 1, fw) != 1) { fclose(fw); return 1; }
            poly_q_set_coeff(sig.v12->entries[i], n, c); 
        } 
    }
    for(size_t k=0; k<PARAM_K; k++) {
        for (size_t i = 0; i < PARAM_D; i++) { 
            int64_t c; 
            for(size_t n=0; n<PARAM_N; n++){ 
                if(fread(&c, sizeof(int64_t), 1, fw) != 1) { fclose(fw); return 1; }
                poly_q_set_coeff(sig.v2[k]->entries[i], n, c); 
            } 
        }
    }
    for (size_t i = 0; i < PARAM_K; i++) { 
        int64_t c; 
        for(size_t n=0; n<PARAM_N; n++){ 
            if(fread(&c, sizeof(int64_t), 1, fw) != 1) { fclose(fw); return 1; }
            poly_q_set_coeff(sig.v3->entries[i], n, c); 
        } 
    }
    fclose(fw);
    
    //PHASE 2: LOCAL AUTHORIZATION CHECK
    clock_gettime(CLOCK_MONOTONIC, &end);
    time_io_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;

    // The Prover locally verifies if the signature mathematically corresponds to the 
    // requested attribute. If false, it gracefully aborts before executing heavy ZKP math.
    if (!osig_user_verify(&sig, &pk, &upk, msg)) {
        printf("{\"status\": \"error\", \"message\": \"The signature in the wallet is invalid!\"}\n");
        return 1;
    }
	
    //PHASE 3: ZKP EMBEDDING
    //Initialize structures for the Zero-Knowledge statement.
    //Initialization of ZKP structures for proof construction + memory allocation for embedded matrices.
    poly_qshow_vec_m1 s1; poly_qshow_vec_m1_init(s1);
    poly_qshow_vec_k u_embed[PARAM_D];
    poly_qshow_mat_k_k A_embed[PARAM_D][PARAM_D], B_embed[PARAM_D][PARAM_D*PARAM_K], A3_embed[PARAM_D][PARAM_K];
    poly_qshow_mat_k_k D_embed[PARAM_D][PARAM_M], Ds_embed[PARAM_D][2*PARAM_D];

    // Common Reference String (CRS): Ensures non-interactivity and prevents tampering. It is generated by a pseudorandom number generator.
    uint8_t crs_seed[CRS_SEED_BYTES]; randombytes(crs_seed, CRS_SEED_BYTES);
    
    // Allocate matrix memory for the ZKP transformation
    for (int i = 0; i < PARAM_D; i++) {
        poly_qshow_vec_k_init(u_embed[i]);
        for (int j = 0; j < PARAM_D; j++) { 
            poly_qshow_mat_k_k_init(A_embed[i][j]); 
            poly_qshow_mat_k_k_init(Ds_embed[i][j]); 
            poly_qshow_mat_k_k_init(Ds_embed[i][j + PARAM_D]); 
        }
        for (int j = 0; j < PARAM_D*PARAM_K; j++) poly_qshow_mat_k_k_init(B_embed[i][j]);
        for (int j = 0; j < PARAM_K; j++) poly_qshow_mat_k_k_init(A3_embed[i][j]);
        for (int j = 0; j < PARAM_M; j++) poly_qshow_mat_k_k_init(D_embed[i][j]);
    }

   
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Transform the standard signature scheme into the ZKP polynomial ring representation
    show_user_embed(A_embed, B_embed, A3_embed, Ds_embed, D_embed, u_embed, s1, &upk, &usk, &pk, &sig, msg);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    time_embed_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
     
    //PHASE 4: FIAT-SHAMIR PROVING
    //Generates the actual ZKP using the Fiat-Shamir heuristic with aborts.
    // This process blinds the signature and create anonymous proof
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    show_user_prove(&proof, A_embed, B_embed, A3_embed, Ds_embed, D_embed, s1, crs_seed, upk.seed);    
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    time_prove_fs_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;

    // Total proof generation time (I/O + Embedding + Fiat-Shamir)
    time_prove_ms = time_io_ms + time_embed_ms + time_prove_fs_ms;

    //Writing public parameters and the generated proof to a binary file.
    FILE *fout = fopen(proof_path, "wb");
    if (!fout) { 
        printf("{\"status\": \"error\", \"message\": \"Cannot write proof\"}\n"); 
        return 1; 
    }
    
    // Write public parameters (CRS and User PK Seed) for the Verifier
    fwrite(crs_seed, 1, CRS_SEED_BYTES, fout);
    fwrite(upk.seed, 1, SEED_BYTES, fout);

    // Save the Public Statement (The matrices defining the problem)
    // checking the validity of the proof
    for (int i = 0; i < PARAM_D; i++) {
        for(size_t k=0; k<PARAM_K_SHOW; k++) save_poly_qshow(fout, u_embed[i][0].entries[k]);
          for (int j = 0; j < PARAM_D; j++) { 
            save_mat_k_k(fout, A_embed[i][j]); 
            save_mat_k_k(fout, Ds_embed[i][j]); 
            save_mat_k_k(fout, Ds_embed[i][j + PARAM_D]); 
        }
        for (int j = 0; j < PARAM_D*PARAM_K; j++) save_mat_k_k(fout, B_embed[i][j]);
        for (int j = 0; j < PARAM_K; j++) save_mat_k_k(fout, A3_embed[i][j]);
        for (int j = 0; j < PARAM_M; j++) save_mat_k_k(fout, D_embed[i][j]);
    }


    //Save the Pure Zero-Knowledge Proof (Blinded vectors)
    //The variables (tA, tB, z1, z2, c) are blinded
    long pos_before_proof = ftell(fout); // Mark position to calculate pure proof size
    
    for(size_t i=0; i<PARAM_D_SHOW; i++) save_poly_qshow(fout, proof.tA[0].entries[i]);
    for(size_t i=0; i<PARAM_ARP_DIV_N_L_SHOW; i++) save_poly_qshow(fout, proof.tB[0].entries[i]);
    fwrite(proof.z3, sizeof(coeff_qshow), PARAM_ARP_SHOW, fout);
    for(size_t i=0; i<PARAM_L_SHOW; i++) save_poly_qshow(fout, proof.h[0].entries[i]);
    save_poly_qshow(fout, proof.t1);

    // Write the cryptographic Challenge (c) and the Masked Secrets (z1, z2)
    save_poly_qshow(fout, proof.c); 
    fwrite(&proof.ctr_c, sizeof(uint32_t), 1, fout);
    for(size_t i=0; i<PARAM_M1_SHOW; i++) save_poly_qshow(fout, proof.z1[0].entries[i]); // The Masked Secret 1
    for(size_t i=0; i<PARAM_M2_SHOW; i++) save_poly_qshow(fout, proof.z2[0].entries[i]); // The Masked Secret 2

    // Measure total and pure proof sizes
    fseek(fout, 0, SEEK_END);
    long total_size_bytes = ftell(fout);
    long pure_proof_bytes = total_size_bytes - pos_before_proof;
    fclose(fout);

    //Pass execution metrics back to the Python backend via JSON stdout
    printf("{\"status\": \"success\", \"time_prove_ms\": %.3f, \"time_embed_ms\": %.3f, \"time_prove_fs_ms\": %.3f, \"time_io_ms\": %.3f, \"proof_size_bytes\": %ld, \"pure_proof_size_bytes\": %ld}\n", 
           time_prove_ms, time_embed_ms, time_prove_fs_ms, time_io_ms, total_size_bytes, pure_proof_bytes);

    //Remove dynamically allocated memory from the FLINT library.
    arith_teardown();
    return 0;
}