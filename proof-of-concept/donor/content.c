#define CMS_CONTENT_TAG (0)

//  Read CMS data.
VSF_PUBLIC int
vsf_content_cms_read (vsf_content_t *impl) {
	VSF_ASSERT (impl);
	
	vsf_impl_t *reader = ???
	size_t len = 0;
	size_t tag;
		
	CHECK_RES (vsf_asn1_reader_read_sequence (reader, &len));
	CHECK_RES (vsf_asn1_reader_read_oid (reader, contentType, &len));
	
	CHECK_RES (vsf_asn1_reader_read_tag (reader, CMS_CONTENT_TAG, &tag, &len));
	CHECK_RES (vsf_asn1_reader_read (reader, content, &len);

	return VSF_OK;
}

//  Write CMS data.
VSF_PUBLIC int
vsf_content_cms_write (vsf_content_t *impl) {
	VSF_ASSERT (impl);
	
	vsf_impl_t *writer = ???
	
    size_t len = 0;

    // checkRequiredField(content); ???
	CHECK_RES (vsf_content_info_cms_write (content, writer, &len));
	CHECK_RES (vsf_asn1_writer_write_tag (writer, CMS_CONTENT_TAG, &len));
	CHECK_RES (vsf_asn1_writer_write_oid (writer, content_type, &len);
	CHECK_RES (vsf_asn1_writer_write_sequence (writer, len);

    return len;
}