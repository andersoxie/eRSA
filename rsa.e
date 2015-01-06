note
	description: "Summary description for {RSA}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	RSA

create
	make

feature

	make
	do
		this_rsa_ptr :=  c_rsa_new
		-- TODO Must call c_rsa_free (this_rsa_ptr) when this object is grabage collected
		this_bio_ptr := c_rsa_bio_new
		-- TODO Need probably also garbage collection
	end

	generate_public_and_private_keys( bits :INTEGER): INTEGER


	-- TODO Might be a better solution to always generate a key. Why otherwise create this calss?
	-- TODO Also add a new create routine that takes a public key and create an RSA object since it is needed to decryt/encrypt
	-- data from somebody else. This might result in that all features can not be called depending on if the private key exists or not. This
	-- must then be a precondition to some routines.
	local
		a_bignum_ptr, a_bn_gencb_ptr: POINTER
	do
		a_bignum_ptr := c_rsa_bignumber_new
		Result := c_rsa_generate_key_ex (this_rsa_ptr, bits, a_bignum_ptr, a_bn_gencb_ptr)
	end

--	write_RSAPublicKey : INTEGER
--	do
--		Result := c_PEM_write_bio_RSAPublicKey ( this_bio_ptr, this_rsa_ptr )
--	end


	RSAPublicKey : STRING
	local
		a_ptr_to_ptr, a_buf_mem_ptr: POINTER
		res : INTEGER
		length_of_buffer : INTEGER
	do
		res := c_PEM_write_bio_RSAPublicKey ( this_bio_ptr, this_rsa_ptr )

		a_ptr_to_ptr := $a_buf_mem_ptr
		bio_get_mem_ptr (a_ptr_to_ptr)
		length_of_buffer := buf_mem_length (a_buf_mem_ptr)
		create Result.make_empty
		Result.from_c_substring (buf_mem_data (a_buf_mem_ptr), 1, length_of_buffer)
	end

	is_RSA_key_valid : BOOLEAN
	do
		Result := c_rsa_check_key (this_rsa_ptr) = 1
	end


    version: INTEGER_64
    do
    	Result := RSA_version (this_rsa_ptr)
    end





	public_encrypt (string_to_encrypt : STRING): STRING
	local
		a_ptr_to_encrypted_data : POINTER
		a_ptr_to_ptr : POINTER
		length : INTEGER
		s : STRING
		result_ptr : POINTER
		a_ptr_to_string_to_encrypt: POINTER
		temp: ANY
	do
		a_ptr_to_encrypted_data := $result_ptr
		a_ptr_to_ptr := $a_ptr_to_encrypted_data
		temp := string_to_encrypt.to_c
		a_ptr_to_string_to_encrypt := $temp
		length := c_rsa_public_encrypt (string_to_encrypt.count, a_ptr_to_string_to_encrypt, a_ptr_to_ptr, this_rsa_ptr)
		create s.make_empty
		s.from_c_substring (a_ptr_to_encrypted_data, 1, length)
		Result := s
	end

	private_decrypt ( string_to_decrypt : STRING ): STRING
	local
		length_of_data_to_decrypt: INTEGER
		a_char_ptr_to_data :POINTER
		temp: ANY
		a_ptr_to_string_to_decrrypt: POINTER
		a_decrypted_c_string : POINTER
	do
			temp := string_to_decrypt.to_c
			a_ptr_to_string_to_decrrypt := $temp
			a_decrypted_c_string := 	c_RSA_private_decrypt (string_to_decrypt.count, a_ptr_to_string_to_decrrypt, this_rsa_ptr  )
			create Result.make_empty
--FIXME Must do the same as with encrypt since it might be data that contains null characters which will then affect this routine.			
			RESULT.from_c (a_decrypted_c_string)
	end


feature {NONE}

		dispose -- TODO Should free the c-allocated resources. Need to find out what name to use. Should redefine an ancestor that is called when the class is garbage collected.
		do
			c_RSA_free (this_RSA_ptr)
		end

	c_RSA_free (a_rsa_ptr: POINTER )
			-- External call to SSL_free
		external
			"C inline use <openssl/rsa.h>"
		alias
			"RSA_free( $a_rsa_ptr)"
		end


	c_rsa_generate_key_ex (a_rsa_ptr : POINTER; bits :INTEGER; a_bignum_ptr : POINTER; a_bn_gencb_ptr : POINTER ): INTEGER
			-- External call to SSL_new
		external
			"C inline use <openssl/rsa.h>"
		alias
			"{
			RAND_poll();
			return (EIF_INTEGER) RSA_generate_key_ex($a_rsa_ptr, $bits, $a_bignum_ptr, NULL)
			}"
		end

	c_RSA_public_encrypt (length_of_data_to_encrypt: INTEGER; a_char_ptr_to_data :POINTER; a_ptr_to_encrypted_data, a_rsa_ptr : POINTER ): INTEGER
			-- External call
		external
			"C inline use <openssl/rsa.h>"
		alias
--		pptr=(char **)ptr;
--		*pptr=(char *)bm;
			"{
			unsigned char * to;
			unsigned char * decrypted;
			int result;
			int result_decryption;
			char **pptr;


			printf ($a_char_ptr_to_data);
			printf("\n");

			to = malloc (RSA_size($a_rsa_ptr)+1);
			result = RSA_public_encrypt($length_of_data_to_encrypt, $a_char_ptr_to_data, to , $a_rsa_ptr, RSA_PKCS1_OAEP_PADDING );
			
			
			pptr=(char **)$a_ptr_to_encrypted_data;
			*pptr=(char *)to;

//			printf ("START a_ptr...->");
//			printf ($a_ptr_to_encrypted_data);
//			printf("<-END");
//			printf("\n");


//			printf ("START->");
//			printf("%i", result);
//			printf("\n");
//			printf (to);
//			printf("<-END");
//			printf("\n");
						
			decrypted = malloc (RSA_size($a_rsa_ptr)+1);
			result_decryption = RSA_private_decrypt(result, to, decrypted, $a_rsa_ptr, RSA_PKCS1_OAEP_PADDING );
			decrypted[result] = 0;
//			printf("%i", result_decryption);
//			printf("\n");
//			printf (decrypted);
//			printf("\n");
//			printf("\n");
			
			return (EIF_INTEGER) result;
			}"
		end

	c_RSA_private_decrypt (length_of_data_to_decrypt: INTEGER; a_char_ptr_to_data :POINTER; a_rsa_ptr : POINTER ): POINTER
			-- External call
		external
			"C inline use <openssl/rsa.h>"
		alias
			"{
			unsigned char * to;
			int result;

//			printf("%i", $length_of_data_to_decrypt);
//			printf("\n");

//			printf ($a_char_ptr_to_data);
//			printf("\n");

			to = malloc (RSA_size($a_rsa_ptr)+1);
			result = RSA_private_decrypt($length_of_data_to_decrypt, $a_char_ptr_to_data, to, $a_rsa_ptr, RSA_PKCS1_OAEP_PADDING );
			to[result] = 0;
//			printf("%i", result);
//			printf("\n");
//			printf (to);
//			printf("\n");
			return (EIF_POINTER) to;
			}"
		end

		c_BIO_get_mem_ptr (a_bio_ptr: POINTER; a_buf_mem_ptr : POINTER )
			-- External call
		external
			"C  use <openssl/bio.h>"
		alias
			"BIO_get_mem_ptr"
		end

	c_PEM_write_bio_RSAPublicKey ( a_bio_ptr : POINTER; a_rsa_ptr: POINTER ): INTEGER
			-- External call
		external
			"C inline use <openssl/pem.h>"
		alias
			" return (EIF_INTEGER) PEM_write_bio_RSAPublicKey($a_bio_ptr, $a_rsa_ptr)"
		end

    RSA_version (p: POINTER): INTEGER_64
            -- Access field x of struct pointed by `p'.
        external
            "C [struct <openssl/rsa.h>] (RSA): EIF_INTEGER_64"
        alias
            "version"
        end

	c_RSA_check_key (a_rsa_ptr: POINTER ): INTEGER
			--
		external
			"C use <openssl/rsa.h>"
		alias
			"RSA_check_key"
		end
		c_RSA_new: POINTER
			external
				"C inline use <openssl/rsa.h>"
			alias
				"return (EIF_POINTER)RSA_new(NULL);"
			end
		c_RSA_bignumber_new: POINTER
			external
				"C inline use <openssl/bn.h>"
			alias
				"{
					BIGNUM *bn = NULL;
					bn  = BN_new(NULL);
					BN_set_word(bn, RSA_F4);
					return (EIF_POINTER) bn;
				}"
			end

		c_RSA_BIO_new: POINTER
			external
				"C inline use <openssl/bio.h>"
			alias
				"{
					BIO *mem = NULL;
					mem  = BIO_new(BIO_s_mem());
					return (EIF_POINTER) mem;
				}"
			end
    BUF_MEM_length (p: POINTER): INTEGER
            -- Access field length of struct pointed by `p'.
        external
            "C [struct <openssl/buffer.h>] (BUF_MEM): EIF_INTEGER"
        alias
            "length"
-- TODO length is typed as size_t and I am not sure about the size of the integer and how it can varies depending on architectures.
        end
    BUF_MEM_data (p: POINTER): POINTER
            -- Access field data (char *) of struct pointed by `p'.
        external
            "C [struct <openssl/buffer.h>] (BUF_MEM): POINTER"
        alias
            "data"
        end


		BIO_get_mem_ptr ( a_buf_mem_ptr : POINTER )
		do
			c_bio_get_mem_ptr (this_bio_ptr, a_buf_mem_ptr)
		end


	this_rsa_ptr : POINTER
	this_bio_ptr : POINTER

end
