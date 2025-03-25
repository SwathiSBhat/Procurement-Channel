import authenticator

def test_authenticator():
    # Test secret key (32 bytes)
    sk = b'\xb2\x19w\xc8\xca\x1c\xbbU\xf0\xa3\xef\xfd\x99f\xe3\xd5\xc9X\x86\x88\xfa\x02\xbfz\r*\xf7\xb66o\x1e\x8f'

    # Create an Authenticator instance with the secret key
    auth = authenticator.Authenticator(sk)
    print("Authenticator initialized with secret key.")

    # Test getDsk method
    dsk = auth.getDsk()
    print(f"Derived secret key (dsk): {dsk}")

    # Test getDpk method
    dpk = auth.getDpk()
    print(f"Derived public key (dpk): {dpk}")

    # Create another Authenticator instance with the derived public key
    auth_pk = authenticator.Authenticator(dpk)
    print("Authenticator initialized with derived public key.")

    # Test authenticate method
    ct = b'some_ctx'  # Context (must be exactly 8 bytes)
    if len(ct) < 8:
        ct = ct.ljust(8, b'\x00')
    elif len(ct) > 8:
        ct = ct[:8]

    st = b'some_statement'  # Statement
    tau = auth.authenticate(ct, st)
    print("Token generated successfully.")
    print(f"Token chs: {tau.chs}")
    print(f"Token rs: {tau.rs}")

    # Test verify method
    is_valid = auth.verify(tau, ct, st)
    print(f"Assertion is valid: {is_valid}")

    # Test verify method with the derived public key
    is_valid_pk = auth_pk.verify(tau, ct, st)
    print(f"Assertion is valid (using derived public key): {is_valid_pk}")

    # Test extract method
    # Create a second statement and token
    st2 = b'another_statement'
    tau2 = auth.authenticate(ct, st2)

    # Extract the secret key using the two tokens
    auth_pk.extract(tau, tau2, ct, st, st2)
    print("Secret key extracted successfully.")

    # Verify the extracted secret key matches the original
    extracted_sk = auth_pk.getDsk()
    #print(f"Extracted secret key: {extracted_sk}")
    extracted_sk_bytes = bytes(extracted_sk)
    print(f"Extracted secret key (bytes): {extracted_sk_bytes}")
    assert extracted_sk_bytes == sk, "Extracted secret key does not match the original!"

    print("All tests passed!")

if __name__ == "__main__":
    test_authenticator()