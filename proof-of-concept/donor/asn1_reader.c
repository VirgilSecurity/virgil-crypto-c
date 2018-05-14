byte * p_;
byte * end_;
vsf_buffer_t * data_;


VSF_PRIVATE int 
_state() {
    if (p_ == 0 || end_ == 0) {
		VSF_LOG_ERROR("ASN.1 Reader isn't initialized");
        return VSF_ERROR;
    }
    if (p_ >= end_) {
        VSF_LOG_ERROR("Attempt to read empty ASN.1 structure.");
		return VSF_ERROR;
    }
	
	return VSF_OK;
}

//  Reset all internal states and prepare to new ASN.1 reading operations.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_reset (vsf_asn1_rd_t *impl, const vsf_buffer_t *item) {
    VSF_ASSERT (impl);
	VSF_ASSERT (item);
	
	data_ = data;
    p_ = data_->data;
    end_ = p_ + data_->size;
}

//  Read ASN.1 type: INTEGER.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read_int (vsf_asn1_rd_t *impl, int *val) {
    VSF_ASSERT (impl);
	VSF_ASSERT (val);
	
	CHECK_RES(_state());
	CHECK_RES(mbedtls_asn1_get_int(&p_, end_, val));
    return VSF_OK;
}

//  Read ASN.1 type: BOOLEAN.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read_bool (vsf_asn1_rd_t *impl, int val) {
    VSF_ASSERT (impl);
	VSF_ASSERT (val);
	
    CHECK_RES(_state());
	CHECK_RES(mbedtls_asn1_get_bool(&p_, end_, val));
    return VSF_OK;
}

//  Read ASN.1 type: NULL.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read_null (vsf_asn1_rd_t *impl) {
    VSF_ASSERT (impl);

    CHECK_RES(_state());
	CHECK_RES(mbedtls_asn1_get_tag(&p_, end_, &len, MBEDTLS_ASN1_NULL));
    return VSF_OK;
}

VSF_PRIVATE int
_read_data (vsf_asn1_rd_t *impl, byte type, const vsf_buffer_t *val) {
    CHECK_RES(_state());
	size_t len;
	CHECK_RES(mbedtls_asn1_get_tag(&p_, end_, &len, type));
    p_ += len;
	vsf_buffer_use(val, p_ - len, len);
	return VSF_OK;
}


//  Read ASN.1 type: OCTET STRING.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read_octet_str (vsf_asn1_rd_t *impl, const vsf_buffer_t *val) {
    VSF_ASSERT (impl);
	VSF_ASSERT (val);
	
	return _read_data(impl, ASN1_OCTET_STRING, val);
}

//  Read ASN.1 type: UTF8String.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read_utf8_str (vsf_asn1_rd_t *impl, const byte *val) {
    VSF_ASSERT (impl);
	VSF_ASSERT (val);
	
	return _read_data(impl, MBEDTLS_ASN1_UTF8_STRING, val);
}

//  Read preformatted ASN.1 structure.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read (vsf_asn1_rd_t *impl, const byte *val) {
    VSF_ASSERT (impl);
	VSF_ASSERT (val);
	
    CHECK_RES(_state());
    size_t len;
    byte *data_start = p_;
    p_ += 1; // Ignore tag value
	CHECK_RES(mbedtls_asn1_get_tag(&p_, end_, &len));
    p_ += len;
	vsf_buffer_use(val, data_start, p_ - len_);
	return VSF_OK;
}

//  Read ASN.1 type: TAG.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read_tag (vsf_asn1_rd_t *impl, size_t *val) {
    VSF_ASSERT (impl);
	VSF_ASSERT (val);
	
    const unsigned char kAsn1Tag_Max = 0x1F;
    if (tag > kAsn1Tag_Max) {
        VSF_ERROR("Requested ASN.1 tag is greater then maximum allowed.");
		return VSF_ERROR;
    }
	
    if (p_ != 0 && end_ != 0 && p_ >= end_) {
        // Expected optional tag located at the end of the ASN.1 structure is absent.
		*val = 0;
        return VSF_OK;
    }
	
    CHECK_RES(_state());
    size_t len;
    int result =
            mbedtls_asn1_get_tag(&p_, end_, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag);
    if (result == 0) {
		*val = len;
        return VSF_OK;
    } else if (result == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
		*val = 0;
        return VSF_OK;
    }
	
	VSF_ERROR("ASN.1 Read Invalid format");
	return VSF_ERROR;
}

//  Read ASN.1 type: OID.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read_oid (vsf_asn1_rd_t *impl, const byte *val) {
    VSF_ASSERT (impl);
	VSF_ASSERT (val);
	
    return _read_data(impl, MBEDTLS_ASN1_OID, val);
}

//  Read ASN.1 type: SEQUENCE.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read_sequence (vsf_asn1_rd_t *impl, size_t *val) {
    VSF_ASSERT (impl);
	VSF_ASSERT (val);
	
    CHECK_RES(_state());
	CHECK_RES(mbedtls_asn1_get_tag(&p_, end_, val, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	return VSF_OK;
}

//  Read ASN.1 type: SET.
VSF_PUBLIC int
vsf_asn1_rd_asn1_reader_read_set (vsf_asn1_rd_t *impl, size_t val) {
    VSF_ASSERT (impl);
	VSF_ASSERT (val);
	
    CHECK_RES(_state());
	CHECK_RES(mbedtls_asn1_get_tag(&p_, end_, val, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
	return VSF_OK;
}