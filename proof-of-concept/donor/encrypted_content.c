#define CMS_ENCRYPTED_CONTENT_TAG (0)

//  Read CMS data.
VSF_PUBLIC int
vsf_encrypted_content_cms_read (vsf_encrypted_content_t *impl) {
	VSF_ASSERT (impl);
	
	vsf_impl_t *reader = ???
	
	CHECK_RES (vsf_asn1_reader_read_sequence (reader, NULL));
	CHECK_RES (vsf_asn1_reader_read_oid (reader, NULL));	// Ignore OID
		
	CHECK_RES (vsf_asn1_reader_read (reader, impl->content_encryption_algorithm));

	size_t tag;

	CHECK_RES (vsf_asn1_reader_read_tag (reader, CMS_ENCRYPTED_CONTENT_TAG, &tag, &len));
	CHECK_RES (vsf_asn1_reader_read (reader, content, &len);

	return VSF_OK;
}

//  Write CMS data.
VSF_PUBLIC int
vsf_encrypted_content_cms_write (vsf_encrypted_content_t *impl) {
	VSF_ASSERT (impl);
	
	vsf_impl_t *writer = ???
		
    size_t len = 0;
    if (!encrypted_Content->empty) {
		CHECK_RES (vsf_asn1_writer_write_octet_string (writer, encrypted_content, &len));
        size_t encrypted_content_len = len;
		CHECK_RES (vsf_asn1_writer_write_tag (writer, CMS_ENCRYPTED_CONTENT_TAG, &len));
    }

    // checkRequiredField(contentEncryptionAlgorithm); ???
	CHECK_RES (vsf_asn1_writer_write_data (writer, content_encryption_algorithm, &len));
	CHECK_RES (vsf_asn1_writer_write_oid (writer, OID_PKCS7_DATA, &len);
	CHECK_RES (vsf_asn1_writer_write_sequence (writer, len);

    return len;	
}