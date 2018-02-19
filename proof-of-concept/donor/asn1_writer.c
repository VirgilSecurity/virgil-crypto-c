#define BUF_LEN_DEFAULT (128)

#define ASN1_TAG_SIZE (1)
#define ASN1_LENGHT_SIZE (3)
#define ASN1_INTEGER_SIZE (ASN1_TAG_SIZE + ASN1_LENGHT_SIZE + 8)
#define ASN1_BOOL_SIZE (3)
#define ASN1_NULL_SIZE (ASN1_TAG_SIZE + 1)
#define ASN1_SIZE_MAX (0xFFFFFFFF) // According to MbedTLS restriction on TAG: LENGTH
#define ASN1_TAG_MAX (0x1E)

#define RETURN_POINTER_DIFF_AFTER_INVOCATION(pointer, invocation) \
do { \
    unsigned char *before = pointer; \
		do { invocation; } while (0); \
    unsigned char *after = pointer; \
    return (ptrdiff_t)(before - after); \
} while(0);

byte * p_;
byte * start_;
vsf_buffer_t * data_;

//  Reset all internal states and prepare to new ASN.1 writing operations.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_reset (vsf_asn1_wr_t *impl, vsf_buffer_t * buffer) {
    VSF_ASSERT (impl);
	VSF_ASSERT (buffer);
	VSF_ASSERT (buffer->size > 0);
	
	data_ = buffer;
}

VSF_PRIVATE int 
_state() {
    if (p_ == 0 || start_ == 0) {
		VSF_LOG_ERROR("ASN.1 Writer isn't initialized");
        return VSF_ERROR;
    }
	
	return VSF_OK;
}

VSF_PRIVATE void 
_ensure_buf_enough(size_t len) {
    CHECK_RES(_state());
	
    size_t unused_space = (size_t) (p_ - start_);
    if (len > unused_space) {
        const size_t used_space = bufLen_ - unused_space;
        const size_t required_len_min = len + used_space;
       if (required_len_min > ASN1_SIZE_MAX) {
		   VSF_LOG_ERROR("ASN.1 structure size limit was exceeded.");
           return VSF_ERROR;
       }
	   
       // const size_t required_len_max =
//                 (size_t) 1 << (size_t) (std::ceil(std::log((double) requiredLenMin) / std::log(2.0)));
//        const size_t adjustedLen = requiredLenMax > kAsn1SizeMax ? kAsn1SizeMax : requiredLenMax;
//        relocateBuffer(adjustedLen);
    }
	return VSF_OK;
}

VSF_PRIVATE void 
_dispose() {
    p_ = 0;
    start_ = 0;
    bufLen_ = 0;
    // if (buf_) {
    //     delete[] buf_;
    //     buf_ = 0;
    // }
}

//  Returns the result ASN.1 structure.
VSF_PUBLIC const vsf_buffer_t *
vsf_asn1_wr_asn1_writer_finish (vsf_asn1_wr_t *impl) {
    VSF_ASSERT (impl);
	
	CHECK_RES(_state());
	vsf_buffer_use(val, p_, bufLen_ - (p_ - start_));
    return VSF_OK;
}

//  Write ASN.1 type: INTEGER.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_int (vsf_asn1_wr_t *impl, int val) {
    VSF_ASSERT (impl);
	
	CHECK_RES(_state());
	CHECK_RES(_ensure_buf_enough(kAsn1IntegerValueSize));
	
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
		CHECK_RES(mbedtls_asn1_write_int(&p_, start_, val));
    );
}

//  Write ASN.1 type: BOOLEAN.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_bool (vsf_asn1_wr_t *impl, int val) {
    VSF_ASSERT (impl);
	
	CHECK_RES(_state());
	CHECK_RES(_ensure_buf_enough(kAsn1BoolValueSize));
	
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
		CHECK_RES(mbedtls_asn1_write_bool(&p_, start_, val));
    );
}

//  Write ASN.1 type: NULL.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_null (vsf_asn1_wr_t *impl) {
    VSF_ASSERT (impl);
	
	CHECK_RES(_state());
	CHECK_RES(_ensure_buf_enough(kAsn1NullValueSize));
	
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
		CHECK_RES(mbedtls_asn1_write_null(&p_, start_));
    );
}

//  Write ASN.1 type: OCTET STRING.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_octet_string (vsf_asn1_wr_t *impl, const vsf_buffer_t *data) {
    VSF_ASSERT (impl);
	VSF_ASSERT (data);
	
	CHECK_RES(_state());
	CHECK_RES(_ensure_buf_enough(kAsn1TagValueSize + kAsn1LengthValueSize + data->size));
	
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
		{
			CHECK_RES(mbedtls_asn1_write_null(&p_, start_));
			CHECK_RES(mbedtls_asn1_write_octet_string(&p_, start_, data->data, data->size));
		}
    );
}

//  Write ASN.1 type: UTF8String.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_utf8_string (vsf_asn1_wr_t *impl, const vsf_buffer_t *data) {
    VSF_ASSERT (impl);
	VSF_ASSERT (data);
	
	CHECK_RES(_state());
	CHECK_RES(_ensure_buf_enough(kAsn1TagValueSize + kAsn1LengthValueSize + data->size));
	
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
		{
			CHECK_RES(mbedtls_asn1_write_raw_buffer(&p_, start_, data.data(), data.size()));
			CHECK_RES(mbedtls_asn1_write_len(&p_, start_, data.size()));
			CHECK_RES(mbedtls_asn1_write_tag(&p_, start_, MBEDTLS_ASN1_UTF8_STRING));
		}
    );
}

//  Write ASN.1 type: UTF8String.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_tag (vsf_asn1_wr_t *impl, size_t tag) {
    VSF_ASSERT (impl);
	CHECK_RES(_state());
	
    if (tag > kAsn1ContextTagMax) {
		VSF_LOG_ERROR("ASN.1 context tag is too big %s, maximum is %s.", tag, kAsn1ContextTagMax);
        return VSF_ERROR;
    }
	
	CHECK_RES(_ensure_buf_enough(kAsn1TagValueSize + kAsn1LengthValueSize));

    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                CHECK_RES(mbedtls_asn1_write_len(&p_, start_, len));
                CHECK_RES(mbedtls_asn1_write_tag(&p_, start_,
                                MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag));
            }
    );
}

//  Write preformatted ASN.1 structure.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_data (vsf_asn1_wr_t *impl, const vsf_buffer_t *data) {
    VSF_ASSERT (impl);
	VSF_ASSERT (data);
	
	CHECK_RES(_state());
	CHECK_RES(_ensure_buf_enough(data->size));
	
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                CHECK_RES(mbedtls_asn1_write_raw_buffer(&p_, start_, data->data, data->size));
            }
    );
}

//  Write ASN.1 type: OID.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_oid (vsf_asn1_wr_t *impl, const vsf_buffer_t *oid) {
    VSF_ASSERT (impl);
	VSF_ASSERT (oid);
	
	CHECK_RES(_state());
	CHECK_RES(_ensure_buf_enough(kAsn1TagValueSize + kAsn1LengthValueSize + oid->size));
	
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                CHECK_RES(mbedtls_asn1_write_oid(&p_, start_, oid->data, oid->size));
            }
    );
}

//  Write ASN.1 type: SEQUENCE.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_sequence (vsf_asn1_wr_t *impl) {
    VSF_ASSERT (impl);
	
	CHECK_RES(_state());
	CHECK_RES(_ensure_buf_enough(kAsn1TagValueSize + kAsn1LengthValueSize));

    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
                CHECK_RES(mbedtls_asn1_write_len(&p_, start_, len));
                CHECK_RES(mbedtls_asn1_write_tag(&p_, start_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            }
    );
}

//  Write ASN.1 type: SET OF ANY.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_set (vsf_asn1_wr_t *impl, const vsf_buffer_t *set, size_t set_sz) {
    VSF_ASSERT (impl);
	VSF_ASSERT (set_sz > 0 && set_sz < 100);
	VSF_ASSERT (set);
	
	CHECK_RES(_state());

    size_t set_len;
	int i;
	set_len = 0;
	
	for (i = 0; i < set_sz; ++i) {
		set_len += set[i].size;
	}
	
	CHECK_RES(_ensure_buf_enough(kAsn1TagValueSize + kAsn1LengthValueSize + set_len));

    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
            {
				for (i = 0; i < set_sz; ++i) {
					CHECK_RES(mbedtls_asn1_write_raw_buffer(&p_, start_, set[i].data, set[i].size));
				}
				
                CHECK_RES(mbedtls_asn1_write_len(&p_, start_, set_len));
                CHECK_RES(mbedtls_asn1_write_tag(&p_, start_, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
            }
    );
}
