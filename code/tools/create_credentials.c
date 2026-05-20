#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include "sep.h"
#include "osig.h"
#include "randombytes.h"
#include "random.h"

// This module simulates the Trusted Authority (Issuer)
// It generates Post-Quantum Lattice-Based keys and securely signs user attributes
// using a Blind Signature protocol over Module Learning With Errors (M-LWE).

//Saves the Authority's public key matrix to disk.
//This function unwraps the dynamic FLINT structures and saves raw 64-bit coefficients.
int save_pk_to_file(const sep_pk_t *pk, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) return 0;
    // Save the public parameter seed
    fwrite(pk->seed, 1, SEED_BYTES, f);
// Iterate over the K x D x D dimensions of the lattice matrix B
    for (size_t k = 0; k < PARAM_K; k++) {
        for (size_t i = 0; i < PARAM_D; i++) {
            for (size_t j = 0; j < PARAM_D; j++) {
                //Extract and save each of the N polynomial coefficients
                for (size_t n = 0; n < PARAM_N; n++) {
                    int64_t coeff = poly_q_get_coeff(pk->B[k]->rows[i]->entries[j], n);
                    fwrite(&coeff, sizeof(int64_t), 1, f);
                }
            }
        }
    }
    fclose(f);
    return 1;
}
//Invoked by the Python Backend via subprocess.
int main(int argc, char *argv[]) {
    if (argc != 7) {
	//The program expects 6 arguments: 3 pairs of (attribute_value, wallet_file_path)
        printf("{\"status\": \"error\", \"message\": \"Spatne argumenty\"}\n");
        return 1;
    }
    // Initialize the algebraic backend (FLINT) and secure randomness
    arith_setup();
    random_init();

    // Variables for performance benchmarking
    struct timespec start, end;
    double t_keygen = 0.0;
    double t_commit = 0.0;
    double t_sign = 0.0;
    long wallet_size_bytes = 0;
    
    // Initialize and generate the Authority's Master Keypair (sk, pk)
    sep_sk_t sk; sep_pk_t pk;
    sep_keys_init(&pk, &sk);
    sep_keygen(&pk, &sk);
    
    // Save the Authority's Public Key to disk
    save_pk_to_file(&pk, "/home/lac/_build/public_key.bin");

    //ISSUANCE LOOP: Generate 3 separate credentials (e.g., Age, License, Record)
    for (int w = 0; w < 3; w++) {
	// Parse the attribute value (0 or 1) and the target destination for the wallet file
        uint8_t attr_value = (uint8_t)atoi(argv[1 + w*2]);
        char *wallet_path = argv[2 + w*2];

        // Declare cryptographic structures
        sep_sig_t sig; user_sk_t usk; user_pk_t upk;
        poly_q_vec_d r[2]; poly_q_vec_d cmt;
        uint8_t state[STATE_BYTES];
        uint8_t msg[PARAM_M*PARAM_N/8];

        // Encode the attribute value into the message buffer
        memset(msg, 0, sizeof(msg));
        msg[0] = attr_value;

        // Allocate memory in FLINT for keys, randomness (r), and commitment (cmt)
        sep_sig_init(&sig); user_keys_init(&upk, &usk);
        poly_q_vec_d_init(r[0]); poly_q_vec_d_init(r[1]); poly_q_vec_d_init(cmt);

        //PHASE 1: User Key Generatione
	// Generates the user's specific keypair linked to the authority's public seed
        clock_gettime(CLOCK_MONOTONIC, &start);
        osig_user_keygen(&upk, &usk, pk.seed);
        clock_gettime(CLOCK_MONOTONIC, &end);
        t_keygen += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;

        //PHASE 2: Cryptographic Commitment
	//The user hides their attribute (msg) inside a lattice commitment (cmt).
        clock_gettime(CLOCK_MONOTONIC, &start);
        
	osig_user_commit(r, cmt, msg, &upk);
        
	clock_gettime(CLOCK_MONOTONIC, &end);
        t_commit += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;

        //PHASE 3: Blind Signature
        // The Authority signs the blinded commitment using its master secret key (sk).
        // The user then incorporates this signature to form the final credential (sig).
        clock_gettime(CLOCK_MONOTONIC, &start);
        
	randombytes(state, STATE_BYTES);
        osig_signer_sign_commitment(&sig, state, &sk, &pk, cmt);
        osig_user_sig_complete(&sig, r);
        
	clock_gettime(CLOCK_MONOTONIC, &end);
        t_sign += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;

        // Write the keys and the signed credential to the user's wallet
	FILE *fw = fopen(wallet_path, "wb");
        if (fw) {
	    // Serialize User Public Key (upk)
            for (size_t i = 0; i < PARAM_D; i++) {
                for (size_t n = 0; n < PARAM_N; n++) {
                    int64_t c = poly_q_get_coeff(upk.t->entries[i], n); fwrite(&c, sizeof(int64_t), 1, fw);
                }
            }
            fwrite(upk.seed, 1, SEED_BYTES, fw);
	    
            // Serialize User Secret Key (usk)
            for(int s=0; s<2; s++) {
                for (size_t i = 0; i < PARAM_D; i++) {
                    for (size_t n = 0; n < PARAM_N; n++) {
                        int64_t c = poly_q_get_coeff(usk.s[s]->entries[i], n); fwrite(&c, sizeof(int64_t), 1, fw);
                    }
                }
            }

	    // Serialize the resulting Signature components (tag, v12, v2, v3)
            for (size_t n = 0; n < PARAM_N; n++) {
                int64_t c = poly_q_get_coeff(sig.tag, n); fwrite(&c, sizeof(int64_t), 1, fw);
            }
            for (size_t i = 0; i < PARAM_D; i++) {
                for (size_t n = 0; n < PARAM_N; n++) {
                    int64_t c = poly_q_get_coeff(sig.v12->entries[i], n); fwrite(&c, sizeof(int64_t), 1, fw);
                }
            }
            for(size_t k=0; k<PARAM_K; k++) {
                for (size_t i = 0; i < PARAM_D; i++) {
                    for (size_t n = 0; n < PARAM_N; n++) {
                        int64_t c = poly_q_get_coeff(sig.v2[k]->entries[i], n); fwrite(&c, sizeof(int64_t), 1, fw);
                    }
                }
            }
            for (size_t i = 0; i < PARAM_K; i++) {
                for (size_t n = 0; n < PARAM_N; n++) {
                    int64_t c = poly_q_get_coeff(sig.v3->entries[i], n); fwrite(&c, sizeof(int64_t), 1, fw);
                }
            }
            
            //Record the size of the generated binary wallet
            if (w == 0) {
                fseek(fw, 0, SEEK_END);
                wallet_size_bytes = ftell(fw);
            }
            fclose(fw);
        }
	// Clean up temporary variables for this loop iteration
        poly_q_vec_d_clear(cmt); poly_q_vec_d_clear(r[1]); poly_q_vec_d_clear(r[0]);
        user_keys_clear(&upk, &usk); sep_sig_clear(&sig);
    }
    // Clean up master keys and FLINT structures
    sep_keys_clear(&pk, &sk);
    arith_teardown();
    
    // OUTPUT: Return averaged benchmarks via JSON to the Python Orchestrator
 	printf("{\"status\": \"success\", \"time_keygen_ms\": %.3f, \"time_commit_ms\": %.3f, \"time_sign_ms\": %.3f, \"time_issue_single_ms\": %.3f, \"wallet_size_bytes\": %ld}\n", 
           t_keygen / 3.0, t_commit / 3.0, t_sign / 3.0, (t_keygen + t_commit + t_sign) / 3.0, wallet_size_bytes);

        return 0;
}