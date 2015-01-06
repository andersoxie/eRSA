note
	description: "[
		Eiffel tests that can be executed by testing tool.
	]"
	author: "EiffelStudio test wizard"
	date: "$Date$"
	revision: "$Revision$"
	testing: "type/manual"

class
	RSA_TEST_SET

inherit
	EQA_TEST_SET
		redefine
			on_prepare,
			on_clean
		end

feature {NONE} -- Events

	on_prepare
			-- <Precursor>
		do
--			assert ("not_implemented", False)
		end

	on_clean
			-- <Precursor>
		do
--			assert ("not_implemented", False)
		end

feature -- Test routines

	RSA_test
			-- New test routine
		local
			r : RSA
			result_from_rsa_feature: INTEGER_32
			test: INTEGER_64
			a_ptr_to_ptr, a_buf_mem_ptr: POINTER
			length_of_buffer: INTEGER_32
			s: STRING_8
			s_enc : STRING
			s_dec: STRING_8
			a_decrypted_c_string: POINTER
			a_ptr_to_string_to_encrypt: POINTER
			a_ptr_to_string_to_decrrypt: POINTER
			temp: ANY
			RSA_public_key_as_string : STRING

		do
			create r.make
			test := r.version
			result_from_rsa_feature := r.generate_public_and_private_keys (1024)

			-- TODO Must change this. Also write a specific test case for this

--			RSA_public_key_as_string := r.rsapublickey
--			a_ptr_to_ptr := $a_buf_mem_ptr
--			r.bio_get_mem_ptr (a_ptr_to_ptr)
--			length_of_buffer := r.buf_mem_length (a_buf_mem_ptr)
--			create s.make_empty
--			s.from_c_substring (r.buf_mem_data (a_buf_mem_ptr), 1, length_of_buffer)



			s := "STRING TO ENCRYPT"
			s_enc := r.public_encrypt (s)
--			Io.put_new_line
--			Io.put_integer (s_enc.count)
--			Io.put_new_line
--			Io.put_string (s_enc)
--			Io.put_new_line
			s_dec := r.private_decrypt (s_enc)
--			Io.put_integer (s_dec.count)
--			Io.put_new_line
--			Io.put_string (s_dec)
--			Io.put_new_line

			assert ("String was encrypted and decrypted", s_dec.is_equal ("STRING TO ENCRYPT"))
		end

		test_of_generating_keys
		local
			r : RSA
			result_from_rsa_feature: INTEGER_32
		do
			create r.make
			result_from_rsa_feature := r.generate_public_and_private_keys (1024)
			assert ("Was able to generate keys", result_from_rsa_feature = 1)

		end

		test_of_public_encrypting_and_then_private_decrypting
		-- Check that it is possible to encrypt with public key and then decrypt with private key and get the same string back.
		local
			r : RSA
			result_from_rsa_feature: INTEGER_32
			s: STRING_8
			encrypted_s : STRING
			a_decrypted_string: STRING

		do
			create r.make
			result_from_rsa_feature := r.generate_public_and_private_keys (1024)

			s := "STRING TO ENCRYPT"

			encrypted_s := r.public_encrypt (s)
			assert ("String was encrypted and decrypted",not  encrypted_s.is_equal ("STRING TO ENCRYPT"))

			a_decrypted_string := r.private_decrypt ( encrypted_s)
			assert ("String was encrypted and decrypted", a_decrypted_string.is_equal ("STRING TO ENCRYPT"))
	end

	test_key_valid
	local
		r: RSA
			result_from_rsa_feature: INTEGER_32
	do
		create r.make
		assert ("Not valid key", not r.is_rsa_key_valid)
		result_from_rsa_feature := r.generate_public_and_private_keys (1024)
		assert ("Not valid key", r.is_rsa_key_valid)

	end

end


