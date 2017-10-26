/*
 * Author: Luis Estrada
 *   Date: 2/29/16
 */

public class Crypto {

    public static int[][] generatePerRoundKeys(int[] key) {
        // permutate key (only uses 56 useful bits)
        int[] p_k = new int[56];
        p_k[0]  = key[56]; p_k[1]  = key[48]; p_k[2]  = key[40];
        p_k[3]  = key[32]; p_k[4]  = key[24]; p_k[5]  = key[16];
        p_k[6]  = key[8];  p_k[7]  = key[0];  p_k[8]  = key[57];
        p_k[9]  = key[49]; p_k[10] = key[41]; p_k[11] = key[33];
        p_k[12] = key[25]; p_k[13] = key[17]; p_k[14] = key[9];
        p_k[15] = key[1];  p_k[16] = key[58]; p_k[17] = key[50];
        p_k[18] = key[42]; p_k[19] = key[34]; p_k[20] = key[26];
        p_k[21] = key[18]; p_k[22] = key[10]; p_k[23] = key[2];
        p_k[24] = key[59]; p_k[25] = key[51]; p_k[26] = key[43];
        p_k[27] = key[35]; p_k[28] = key[62]; p_k[29] = key[54];
        p_k[30] = key[46]; p_k[31] = key[38]; p_k[32] = key[30];
        p_k[33] = key[22]; p_k[34] = key[14]; p_k[35] = key[6];
        p_k[36] = key[61]; p_k[37] = key[53]; p_k[38] = key[45];
        p_k[39] = key[37]; p_k[40] = key[29]; p_k[41] = key[21];
        p_k[42] = key[13]; p_k[43] = key[5];  p_k[44] = key[60];
        p_k[45] = key[52]; p_k[46] = key[44]; p_k[47] = key[36];
        p_k[48] = key[28]; p_k[49] = key[20]; p_k[50] = key[12];
        p_k[51] = key[4];  p_k[52] = key[27]; p_k[53] = key[19];
        p_k[54] = key[11]; p_k[55] = key[3];

        int[][] cn = new int[17][28]; // C0,C1...,C26
        int[][] dn = new int[17][28]; // D0,D1,...,D26

        // Split 56-bit permutated key p_k into 2 halves cn[0] and dn[0]
        System.arraycopy(p_k, 0, cn[0], 0, 28); // C0
        System.arraycopy(p_k, 28, dn[0], 0, 28); // D0

        // Cn and Dn, 1 <= n <= 16, stored as cn[1...16] and dn[1...16],
        // respectively, are blocks from from the previous pair Cn-1 and Dn-1,
        // respectively, using a series of left-shifts of the previous blocks.
        for (byte i = 1; i < 17; i++) {
            for (byte j = 0; j < 26; j++) {
                if (i != 1 && i != 2 && i != 9 && i != 16) {
                    cn[i][j] = cn[i-1][j+2]; // 2 left-shifts
                    dn[i][j] = dn[i-1][j+2];
                } else {
                    cn[i][j] = cn[i-1][j+1]; // 1 left-shift
                    dn[i][j] = dn[i-1][j+1];
                }
            }
            // move bits that were in the front to the back after left-shifts
            if (i != 1 && i != 2 && i != 9 && i != 16) {
                cn[i][26] = cn[i-1][0];
                cn[i][27] = cn[i-1][1];
                dn[i][26] = dn[i-1][0];
                dn[i][27] = dn[i-1][1];
            } else {
                cn[i][26] = cn[i-1][27];
                cn[i][27] = cn[i-1][0];
                dn[i][26] = dn[i-1][27];
                dn[i][27] = dn[i-1][0];
            }
        }

        // concatenate cn and dn into cndn, removing bits 9, 18, 22, 25
        int[][] cndn = new int[16][56];
        for (byte i = 0; i < 16; i++) {
            for (byte j = 0; j < 28; j++) {
                cndn[i][j] = cn[i+1][j];
                cndn[i][j+28] = dn[i+1][j];
            }
        }

        // generate per-round keys by permutating cndn
        int[][] kn = new int[16][48]; // 16 48-bit keys
        for (byte i = 0; i < 16; i++) {
            kn[i][0]  = cndn[i][13]; kn[i][1]  = cndn[i][16];
            kn[i][2]  = cndn[i][10]; kn[i][3]  = cndn[i][23];
            kn[i][4]  = cndn[i][0];  kn[i][5]  = cndn[i][4];
            kn[i][6]  = cndn[i][2];  kn[i][7]  = cndn[i][27];
            kn[i][8]  = cndn[i][14]; kn[i][9]  = cndn[i][5];
            kn[i][10] = cndn[i][20]; kn[i][11] = cndn[i][9];
            kn[i][12] = cndn[i][22]; kn[i][13] = cndn[i][18];
            kn[i][14] = cndn[i][11]; kn[i][15] = cndn[i][3];
            kn[i][16] = cndn[i][25]; kn[i][17] = cndn[i][7];
            kn[i][18] = cndn[i][15]; kn[i][19] = cndn[i][6];
            kn[i][20] = cndn[i][26]; kn[i][21] = cndn[i][19];
            kn[i][22] = cndn[i][12]; kn[i][23] = cndn[i][1];
            kn[i][24] = cndn[i][40]; kn[i][25] = cndn[i][51];
            kn[i][26] = cndn[i][30]; kn[i][27] = cndn[i][36];
            kn[i][28] = cndn[i][46]; kn[i][29] = cndn[i][54];
            kn[i][30] = cndn[i][29]; kn[i][31] = cndn[i][39];
            kn[i][32] = cndn[i][50]; kn[i][33] = cndn[i][44];
            kn[i][34] = cndn[i][32]; kn[i][35] = cndn[i][47];
            kn[i][36] = cndn[i][43]; kn[i][37] = cndn[i][48];
            kn[i][38] = cndn[i][38]; kn[i][39] = cndn[i][55];
            kn[i][40] = cndn[i][33]; kn[i][41] = cndn[i][52];
            kn[i][42] = cndn[i][45]; kn[i][43] = cndn[i][41];
            kn[i][44] = cndn[i][49]; kn[i][45] = cndn[i][35];
            kn[i][46] = cndn[i][28]; kn[i][47] = cndn[i][31];
        }

        return kn;
    }

    /** this method implements the DES encryption algorithm */
    public static int[] DES(int[] plaintext, int[] key) {
        if (plaintext.length != 64 || key.length != 64) {
            System.err.println("Size not 64");
            System.exit(1);
        }

        int[][] kn = new int[16][48];
        kn = generatePerRoundKeys(key);



        // initial permutation of plaintext
        int[] IP = new int[64];
        for (byte i = 0; i < 8; i++) {
            IP[(8*5) - (i+1)] = plaintext[(8*i) + 0]; // A
            IP[(8*1) - (i+1)] = plaintext[(8*i) + 1]; // B
            IP[(8*6) - (i+1)] = plaintext[(8*i) + 2]; // C
            IP[(8*2) - (i+1)] = plaintext[(8*i) + 3]; // D
            IP[(8*7) - (i+1)] = plaintext[(8*i) + 4]; // E
            IP[(8*3) - (i+1)] = plaintext[(8*i) + 5]; // F
            IP[(8*8) - (i+1)] = plaintext[(8*i) + 6]; // G
            IP[(8*4) - (i+1)] = plaintext[(8*i) + 7]; // H
        }

        // DES rounds: generate 32-bit Ln and Rn, 1 <= n <= 16
        int[][] Ln = new int[17][32];
        int[][] Rn = new int[17][32];
        System.arraycopy(IP, 0, Ln[0], 0, 32); // L0
        System.arraycopy(IP, 32, Rn[0], 0, 32); // R0
        int[][] mangler_result = new int[16][32];

        for (byte i = 1; i < 17; i++) {
            Ln[i] = Rn[i-1]; // Ln = Rn-1

            // Rn = Ln-1 XOR mangler(Rn-1, Kn)
            mangler_result[i-1] = mangler(Rn[i-1], kn[i-1]);
            for (byte j = 0; j < 32; j++) {
                Rn[i][j] = Ln[i-1][j] ^ mangler_result[i-1][j];
            }
        }

        // R16L16 holds the reversed final 64-bit block from the 16th DES round
        int[] R16L16 = new int[64];
        for (byte i = 0; i < 32; i++) {
            R16L16[i] = Rn[16][i];
            R16L16[i+32] = Ln[16][i];
        }

        // we apply a final permutation to R16L16 to obtain the DES ciphertext
        int[] ciphertext = new int[64];
        for (byte i = 0; i < 8; i++) {
            ciphertext[(8*i) + 0] = R16L16[(8*5) - (i+1)]; // A
            ciphertext[(8*i) + 1] = R16L16[(8*1) - (i+1)]; // B
            ciphertext[(8*i) + 2] = R16L16[(8*6) - (i+1)]; // C
            ciphertext[(8*i) + 3] = R16L16[(8*2) - (i+1)]; // D
            ciphertext[(8*i) + 4] = R16L16[(8*7) - (i+1)]; // E
            ciphertext[(8*i) + 5] = R16L16[(8*3) - (i+1)]; // F
            ciphertext[(8*i) + 6] = R16L16[(8*8) - (i+1)]; // G
            ciphertext[(8*i) + 7] = R16L16[(8*4) - (i+1)]; // H
        }

        return ciphertext; // finally!
    }

    /** mangler function */
    static int[] mangler(int[] block, int[] key) {

        int[] E_block = E(block); // expand block to 48 bits

        int[] result = new int[48]; // result = Kn XOR E(Rn-1)
        for (byte i = 0; i < 48; i++) {
            result[i] = E_block[i] ^ key[i];
        }

        // 8 groups of 6 bits are used as addresses to S-boxes
        int[][] B = new int[8][6];
        for (int i = 0; i < 8; i++) {
            System.arraycopy(result, i*6, B[i], 0, 6);
        }

        // translate each 6 bits of B into rows and columns of S-boxes
        String[] rows_bin = new String[8];
        String[] cols_bin = new String[8];
        for (byte i = 0; i < 8; i++) {
            rows_bin[i] = "" + B[i][0] + B[i][5]; // 2 outer bits
            cols_bin[i] = "" + B[i][1] + B[i][2] + B[i][3] + B[i][4]; // 4 inner
        }

        // translate rows and columns to decimal
        int[] rows_dec = new int[8];
        int[] cols_dec = new int[8];
        for (byte i = 0; i < 8; i++) {
            rows_dec[i] = Integer.parseInt(rows_bin[i], 2);
            cols_dec[i] = Integer.parseInt(cols_bin[i], 2);
        }

        // each value in B will be an index to each S-box for a certain value
        byte[][][] SBOX = {
            { {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} },
            { {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9} },
            { {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12} },
            { {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14} },
            { {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3} },
            { {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13} },
            { {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12} },
            { {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} } };

        // S-box values are found in decimal, then converted to binary strings
        String[] sbox_values = new String[8];
        for (byte i = 0; i < 8; i++) {
            sbox_values[i] =
                    Integer.toBinaryString(SBOX[i][rows_dec[i]][cols_dec[i]]);
        }
        for (byte i = 0; i < 8; i++) {
            while (sbox_values[i].length() < 4) {
                sbox_values[i] = "0" + sbox_values[i]; // padding
            }
        }

        // S-box output is an array of bits
        int[] sbox_output = new int[32];
        for (byte i = 0; i < 8; i++) {
            for (byte j = 0; j < 4; j++) {
                sbox_output[j+(i*4)] =
                        Integer.parseInt(sbox_values[i].substring(j,j+1));
            }
        }

        // permutate the S-box output to get the result of the mangler function
        int[] m_result = new int[32];
        m_result[0]  = sbox_output[15]; m_result[1]  = sbox_output[6];
        m_result[2]  = sbox_output[19]; m_result[3]  = sbox_output[20];
        m_result[4]  = sbox_output[28]; m_result[5]  = sbox_output[11];
        m_result[6]  = sbox_output[27]; m_result[7]  = sbox_output[16];
        m_result[8]  = sbox_output[0];  m_result[9]  = sbox_output[14];
        m_result[10] = sbox_output[22]; m_result[11] = sbox_output[25];
        m_result[12] = sbox_output[4];  m_result[13] = sbox_output[17];
        m_result[14] = sbox_output[30]; m_result[15] = sbox_output[9];
        m_result[16] = sbox_output[1];  m_result[17] = sbox_output[7];
        m_result[18] = sbox_output[23]; m_result[19] = sbox_output[13];
        m_result[20] = sbox_output[31]; m_result[21] = sbox_output[26];
        m_result[22] = sbox_output[2];  m_result[23] = sbox_output[8];
        m_result[24] = sbox_output[18]; m_result[25] = sbox_output[12];
        m_result[26] = sbox_output[29]; m_result[27] = sbox_output[5];
        m_result[28] = sbox_output[21]; m_result[29] = sbox_output[10];
        m_result[30] = sbox_output[3];  m_result[31] = sbox_output[24];

        return m_result;
    }

    /** this method expands 32-bit blocks to 48 bits for the mangler function */
    static int[] E(int[] arr) {

        int[] E = new int[48];
        E[0] = arr[31];
        for (byte i = 1;  i < 6;  i++) E[i] = arr[i-1];
        for (byte i = 6;  i < 12; i++) E[i] = arr[i-3];
        for (byte i = 12; i < 18; i++) E[i] = arr[i-5];
        for (byte i = 18; i < 24; i++) E[i] = arr[i-7];
        for (byte i = 24; i < 30; i++) E[i] = arr[i-9];
        for (byte i = 30; i < 36; i++) E[i] = arr[i-11];
        for (byte i = 36; i < 42; i++) E[i] = arr[i-13];
        for (byte i = 42; i < 47; i++) E[i] = arr[i-15];
        E[47] = arr[0];

        return E;
    }

    /** this method implements the ECB encryption algorithm */
    static int[] ECB(String plaintext, String key) {
        int[] p = string_to_binary(plaintext);
        int[] k_initial = string_to_binary(key);
        int[] k = new int[64];

        if (k_initial.length < 64) {
            System.err.println("Size of key is less than 64");
            System.exit(1);
        } else { // use only first 64 bits of key
            System.arraycopy(k_initial, 0, k, 0, 64);
        }

        int full_blocks = p.length / 64;

        int[][] pn; // pn holds 64-bit blocks to be put through DES algorithm

        if (p.length % 64 > 0) { // if a block is less than 64-bits
            pn = new int[full_blocks+1][64];
            for (int i = 0; i < pn.length-1; i++) {
                System.arraycopy(p, (i*64), pn[i], 0, 64); // save full blocks
            }
            // save last block; System.arraycopy() adds padding to last block
            System.arraycopy(p,full_blocks*64, pn[pn.length-1],0, p.length%64);

        } else { // if all blocks are 64-bits
            pn = new int[full_blocks][64];
            for (int i = 0; i < pn.length; i++) {
                System.arraycopy(p, (i*64), pn[i], 0, 64);
            }
        }

        // perform DES on all blocks
        int[][] encrypted_blocks = new int[pn.length][64];
        for (int i = 0; i < encrypted_blocks.length; i++) {
            encrypted_blocks[i] = DES(pn[i], k);
        }

        // concatenate encrypted blocks into an array
        int[] encrypted_arr = new int[encrypted_blocks.length*64];
        for (int i = 0; i < encrypted_arr.length / 64; i++) {
            System.arraycopy(encrypted_blocks[i], 0, encrypted_arr, (i*64), 64);
        }

        // get 8-bit binary strings of ciphertext
        String[] ciphertext_string = new String[encrypted_arr.length / 8];
        for (int i = 0; i < encrypted_arr.length / 8; i++) {
            ciphertext_string[i] = "";
            for (int j = 0; j < 8; j++) {
                ciphertext_string[i] += encrypted_arr[(i*8)+j];
            }
        }

        // ciphertext is the binary strings converted to decimal integers
        int[] ciphertext = new int[ciphertext_string.length];
        for (int i = 0; i < ciphertext.length; i++) {
            int decimal = Integer.parseInt(ciphertext_string[i], 2);
            ciphertext[i] = decimal;
        }

        return ciphertext;
    }

    /** this method implements the CBC encryption algorithm */
    static int[] CBC(String plaintext, String key, String IV) {
        int p[] = string_to_binary(plaintext);
        int k_initial[] = string_to_binary(key);
        int iv_initial[] = string_to_binary(IV);
        int k[] = new int[64];
        int iv[] = new int[64];

        if (k_initial.length < 64 || iv_initial.length < 64) {
            System.err.println("Size of key or IV is less than 64");
            System.exit(1);
        } else { // use only first 64 bits of key and IV
            System.arraycopy(k_initial, 0, k, 0, 64);
            System.arraycopy(iv_initial, 0, iv, 0, 64);
        }

        int full_blocks = p.length / 64;
        int num_blocks = full_blocks;

        int[][] pn; // pn holds 64-bit blocks to be put through DES algorithm

        if (p.length % 64 > 0) { // if a block is less than 64-bits
            num_blocks += 1;

            pn = new int[full_blocks+1][64];
            for (int i = 0; i < pn.length-1; i++) {
                System.arraycopy(p, (i*64), pn[i], 0, 64); // save full blocks
            }
            // save last block; System.arraycopy() adds padding to last block
            System.arraycopy(p,full_blocks*64, pn[pn.length-1],0, p.length%64);

        } else { // if all blocks are 64-bits
            pn = new int[full_blocks][64];
            for (int i = 0; i < pn.length; i++) {
                System.arraycopy(p, (i*64), pn[i], 0, 64);
            }
        }

        // XOR Initialization Vector with first block of plaintext
        int[][] iv_2d = arr_1d_to_2d(iv);
        int[][] first_xor = new int[1][64];
        for (int i = 0; i < first_xor.length; i++) {
            for (int j = 0; j < first_xor[0].length; j++) {
                first_xor[i][j] = iv_2d[i][j] ^ pn[0][j];
            }
        }

        // encrypt result of the XOR to result in c1
        int[][] ci = new int[num_blocks][64];
        ci[0] = DES(first_xor[0], k);

        // XOR each ci with the next plaintext block, then encrypt each with DES
        int[][] xor = new int[num_blocks-1][64];
        for (int i = 1; i < num_blocks; i++) {
            for (int j = 0; j < 64; j++) {
                xor[i-1][j] = ci[i-1][j] ^ pn[i][j];
                ci[i] = DES(xor[i-1], k);
            }
        }

        // get 8-bit binary strings of ciphertext
        int[] encrypted_arr = arr_2d_to_1d(ci);
        String[] ciphertext_string = new String[encrypted_arr.length / 8];
        for (int i = 0; i < encrypted_arr.length / 8; i++) {
            ciphertext_string[i] = "";
            for (int j = 0; j < 8; j++) {
                ciphertext_string[i] += encrypted_arr[(i*8)+j];
            }
        }

        // ciphertext is the binary strings converted to decimal integers
        int[] ciphertext = new int[ciphertext_string.length];
        for (int i = 0; i < ciphertext.length; i++) {
            int decimal = Integer.parseInt(ciphertext_string[i], 2);
            ciphertext[i] = decimal;
        }

        return ciphertext;
    }

    /** this helper method converts strings into their binary representations */
    static int[] string_to_binary(String str) {
        int[] arr = new int[str.length()*8]; // array to be returned

        for (int i = 0; i < str.length(); i++) {
            // convert characters in key to binary strings
            String s = Integer.toBinaryString(str.charAt(i));
            while (s.length() < 8) {
                s = "0" + s; // padding of binary strings
            }
            // put each binary digit into p array
            for (int j = 0; j < 8; j++) {
                arr[j+(i*8)] = Integer.parseInt(s.substring(j, j+1));
            }
        }
        return arr;
    }

    /** this helper method returns a 1d equivalent array of a 2d array */
    static int[] arr_2d_to_1d(int[][] arr_2d) {
        int[] arr_1d = new int[arr_2d.length*arr_2d[0].length];
        for (byte i = 0; i < arr_2d.length; i++) {
            for (byte j = 0; j < arr_2d[0].length; j++) {
                arr_1d[(i*arr_2d[0].length)+j] = arr_2d[i][j];
            }
        }
        return arr_1d;
    }

    /** this helper method returns a 2d equivalent array of a 1d array */
    static int[][] arr_1d_to_2d(int[] arr_1d) {
        int[][] arr_2d = new int[arr_1d.length/64][64];
        for (byte i = 0; i < arr_1d.length/64; i++) {
            for (byte j = 0; j < 64; j++) {
                arr_2d[i][j] = arr_1d[(i*64)+j];
            }
        }
        return arr_2d;
    }

    /** print 1d arrays */
    static void print(int[] arr) {
        for (int i = 0; i < arr.length; i++) {
            System.out.print(arr[i]);
            if (arr.length == 64) {
                if ((i+1) % 8 == 0) System.out.print(" ");
            } else if (arr.length == 56) {
                if ((i+1) % 7 == 0) System.out.print(" ");
            } else if (arr.length == 48) {
                if ((i+1) % 6 == 0) System.out.print(" ");
            } else if (arr.length == 32) {
                if ((i+1) % 4 == 0) System.out.print(" ");
            } else if (arr.length == 28) {
                if ((i+1) % 7 == 0) System.out.print(" ");
            } else if (arr.length == 24) {
                if ((i+1) % 8 == 0) System.out.print(" ");
            } else if (arr.length == 8) {
                if ((i+1) % 1 == 0) System.out.print(" ");
            } else {
                if ((i+1) % 8 == 0) System.out.print(" ");
            }
        }
        System.out.println();
    }

    /** print 2d arrays */
    static void print(int[][] arr) {
        for (int i = 0; i < arr.length; i++) {
            print(arr[i]);
        }
        System.out.println();
    }

    /** I'm lazy, ok? */
    static void p(String s) {
        System.out.println(s);
    }

    public static void main(String[] args) {
        int[] plaintext_DES = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1,
            0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1};
        int[] key_DES = {0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0,
            0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0,
            1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 0, 0, 0, 1};

        int[] ciphertext_DES = DES(plaintext_DES, key_DES);
        p("DES");
        print(ciphertext_DES);

        String plaintext_ECB_1 = "I LOVE SECURITY";
        String key_ECB_1 = "ABCDEFGH";
        String plaintext_ECB_2 = "GO GATORS!";
        String key_ECB_2 = "ABCDEFGH";

        p("ECB_1");
        int[] ciphertext_ECB_1 = ECB(plaintext_ECB_1, key_ECB_1);
        for (int i = 0; i < ciphertext_ECB_1.length; i++) {
            System.out.print(ciphertext_ECB_1[i] + " ");
        }
        p("");

        p("ECB_2");
        int[] ciphertext_ECB_2 = ECB(plaintext_ECB_2, key_ECB_2);
        for (int i = 0; i < ciphertext_ECB_2.length; i++) {
            System.out.print(ciphertext_ECB_2[i] + " ");
        }
        p("");

        String plaintext_CBC_1 = "I LOVE SECURITY";
        String key_CBC_1 = "ABCDEFGH";
        String IV_1 = "ABCDEFGH";
        String plaintext_CBC_2 = "SECURITYSECURITY";
        String key_CBC_2 = "ABCDEFGH";
        String IV_2 = "ABCDEFGH";

        p("CBC_1");
        int[] ciphertext_CBC = CBC(plaintext_CBC_1, key_CBC_1, IV_1);
        for (int i = 0; i < ciphertext_CBC.length; i++) {
            System.out.print(ciphertext_CBC[i] + " ");
        }
        p("");

        p("CBC_2");
        int[] ciphertext_CBC_2 = CBC(plaintext_CBC_2, key_CBC_2, IV_2);
        for (int i = 0; i < ciphertext_CBC_2.length; i++) {
            System.out.print(ciphertext_CBC_2[i] + " ");
        }
        p("");
    }

}
