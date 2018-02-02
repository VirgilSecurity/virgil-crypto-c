#define ANS1_CUSTOM_PARAMS_TAG (0)
#define ANS1_CONTENT_INFO_VERSION (0)

//  Read CMS data.
VSF_PUBLIC int
define_size (vsf_content_info_t *impl, const vsf_buffer_t * data) {
    VSF_ASSERT (impl);
	VSF_ASSERT (data);

	if (data->size) {
		return VSF_ERROR;
	}
	
	byte * p_begin, p_end, p;
	p = p_begin = data->data;
	p_end = p_begin + data->size;
	
	// Validate TAG
    if (*p != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return VSF_ERROR;
    }
    ++p;
	
    // Read length
	vsf_impl_t *reader = ???
    size_t size = 0;
	
	// TODO: Fix it
    int result = vsf_asn1_reader_read_len(&p, p_end, &size);
    if (result == 0 || result == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
        size += p - p_begin;
    } else {
        return VSF_ERROR;
    }
    // Validate ContentInfo version
    int version = 0;
	CHECK_RES (vsf_asn1_reader_read_int (reader, &version));
    result = mbedtls_asn1_get_int(&p, p_end, &version);
    if (version != ANS1_CONTENT_INFO_VERSION) {
        return VSF_ERROR;
    }
    return size;
}

//  Read CMS data.
VSF_PUBLIC int
vsf_content_info_cms_read (vsf_content_info_t *impl) {
	VSF_ASSERT (impl);
	
	vsf_impl_t *reader = ???
	size_t sz;
	int version;
		
	CHECK_RES (vsf_asn1_reader_read_sequence (reader, &sz));
	CHECK_RES (vsf_asn1_reader_read_int (reader, &version));
	
    if (ANS1_CONTENT_INFO_VERSION != version) {
		VSF_LOG_ERROR ("Unsupported version of CMS Content Info.");
        return VSF_ERROR;
    }
	
	CHECK_RES (vsf_asn1_reader_read (reader, NULL);
	
	size_t tag;
	CHECK_RES (vsf_asn1_reader_read_tag (reader, &tag);
	
	if (tag > 0) {
        CHECK_RES (vsf_asn1_reader_read (reader, NULL);
    }
	
	return VSF_OK;
}

//  Write CMS data.
VSF_PUBLIC int
vsf_content_info_cms_write (vsf_content_info_t *impl) {
	VSF_ASSERT (impl);
	
	vsf_impl_t *writer = ???
	
    size_t len = 0;
    if (!custom_params->empty()) {
		CHECK_RES (vsf_content_info_cms_write (custom_params, writer, &len));
		CHECK_RES (vsf_asn1_writer_write_tag (writer, ASN1_CUSTOM_PARAMS_TAG, &len));
    }

	CHECK_RES (vsf_content_info_cms_write (custom_content, writer, &len));
	CHECK_RES (vsf_asn1_writer_write_int (writer, ANS1_CONTENT_INFO_VERSION, &len));
	CHECK_RES (vsf_asn1_writer_write_sequence (writer, len?, &len);

    return len;
}