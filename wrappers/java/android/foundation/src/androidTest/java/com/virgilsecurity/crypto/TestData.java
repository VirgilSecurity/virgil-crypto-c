package virgil.crypto;

import android.util.Base64;

public class TestData {
    public static final byte[] data = Base64.decode(
            "2saYMwjfh6ZKmpzS8Gn71+Wl/DnURsjGIWcAAshaHnH32RDhpZSem6l5HhvLG0TZ5F7b1cDzB" +
                    "9Bk4XomxINviHozt3KZ3DmBKZitQAIU9/6/qCnJzuxbHgOteIFsE65WfOEmrVbK8sRZuVvp2MY" +
                    "bG/5FoCb6hTlHTgQHv5xafd0b8J/aAzGKm2r4Ug9kUQSwc1PgnzSazXh5z4Z1RYyMGPel/yv6Z" +
                    "fUWs5gDKRJAImuvzGL64fUCmxz9Fifua2G5t9DTpErTUIcuZgtuIqU9UoogJIxbkftxtGrBxzB" +
                    "MWveCIdsUNlqiT/ileOAofwiPn9V91Wybhk8gXSwIOV2B5YeZhNmzhZXK1JZKVIpvSIrNPuDJ1" +
                    "1NdSCSJ0hpKSwuZdQZAIu6Mm3apgVFJBcEQNbc/Xh3PtTDx6asDqDktmywDj7E6xCUZZP9Z0A0" +
                    "pvsbzRSE9+X7y0V57sy8r8MKlVWlPGu5JJ4zLh+6BSthX6pshdvrNgLv/g0p3PgLsA47S5QWIb" +
                    "0L80sSQqePKyxvdWjsPepVlXaIOqgD2Db/9VHE4z51SquX/U5Lh5w4NeyEpRgBOvDKqgJVTY7H" +
                    "gjgL3zybzBwkxDWJjp7lx9X5gzKI4tEoV4LO3PuEl6h6TJ9BA+sDsCLhnrs0NkjyZURcju84R2" +
                    "a7cVn8GVTpW45wTom7/e+w41mdyTqUIEUyOgZ/GBbC4HYaUBXWShpyuih0VdQhYgn5WgDoKd4l" +
                    "pdpGe1MOiGiTVsr1q4eH84ajTus4j6YXYU7d2FmMsb+gDiWHtoKwmiXAqbShXbUSxwQE+dwv7T" +
                    "2Eaq4Vl+ZKzQe/617947FZHZylSbdLI8f6IMeVIxZxGx3eYTxQMHDB6cjugrmd0UCZ/4co3z2R" +
                    "PTHKVOAKfrXwGaxqhtuZgbp5a+a/SpRVfdnb2TjkWG7YqkfK4VXYS1MDvfwMnr5cIUwCyaicJ5" +
                    "wkNywKqzEmodaHEI94wGDZaH/ZJH5avIJrgcDsIs+/Ft483DwaJ9CxNOLWUZXTphLTSLbDuMy3" +
                    "9P51lO0vl1s5jvnwgxjvCqnOo/8fw9/fvnASjHcDc9lSp1cGth6aS5mGwUKgwUxuKMHZk0/Py0" +
                    "2tuTHSwCHQa77eXcWL50CsyMzXaEOoDkhoE9drg8yS7ccH4+LwG15q9sACufWoO66Bqy/I2P7N" +
                    "vCGB49KwVV7B/GECHRTSRk0/88N31KVT6XaHfhek/cDjp77ISCfwQE5acKqqJibzyW3dHhBZSd" +
                    "1Rce0XIbqmFKbZxhpJc9posuulG/3SPt9Q9UwbvAF+Tb9a7HK/+oG6PSh7GMiB/p/B263skKkK" +
                    "bmHGGA6UnFT0sxGmUAUU+uE7loa2sYQo+4Q==",
            Base64.NO_WRAP);

    public static final byte[] ed25519_private_key = Base64.decode("BCC7jU3FE57s4k+DVN3G/QphrGMQ4WrHIogTBcBHQuPIRg==",
            Base64.NO_WRAP);
    public static final byte[] ed25519_public_key = Base64.decode("4eO0V6xoGEyBlqEVX4YckF+YmDDH99Zjm2cY1y3+A4E=",
            Base64.NO_WRAP);
    public static final byte[] ed25519_signature = Base64.decode("CauBQA1rLw55f5Fo6VvkoglA8/EhQDtWc6nNxCxXtdoIs5M5cJVfuM30JWAIDzUj735uo98ovg/mizXFNt0fCQ==",
            Base64.NO_WRAP);
    public static final byte[] ed25519_wrong_signature = Base64.decode("ziuGneVnQ9isQQIl6nSkOlrqNH0QUaeAWISeXAuepMCpBsY4ORYwR6ZtVGaIs8U63n4FLuiz3Q31Uzfdv15gAg==",
            Base64.NO_WRAP);

    public static final byte[] aes256_cbc_key = Base64.decode("YD3rEBXKcb4rc67whX13gR81LAc7YQjXLZgQowkU3/Q=",
            Base64.NO_WRAP);
    public static final byte[] aes256_cbc_iv = Base64.decode("AAECAwQFBgcICQoLDA0ODw==",
            Base64.NO_WRAP);
    public static final byte[] aes256_cbc_encrypted_data = Base64.decode("B+LvBFKsqAzMA+0tIFelJ1GvZmuleX8loz5zRKXCrp+XoxyAG7yMGi2l/gDWWDCjYRUOK0UBhFz1WGa3oBbKhRd83w0IGdyc82QC0UjnvVCXbF+TeRPhnXG1J/2OX/uyFkT50m8IY27sgwIan+s+SFfMR5TIaXbtsx8ftrW7pWsQvxkzWZ15+1yVAfaZic4q/rCr5lGOSaE98gL3fBafO8rTt6ar6AiK2rfi9eaelu5WRKApCnhGflD8pWrCyNJJ1Zw4qfX6fxmwXMeYlSNLRMLwWbadkwb/Rf0Q+rwP5hAbsuz+rfZZJOQyKqL8uGItAGUpsYhVcNEXRk8KfMXglQ2WjFXZKfI1HA7Nv7DpkerRXmntWG8n0LRUNb5A0BR2HQxkek43igWF3pirPDblVflmmVdmU5IyxOrkzTP8L3uJIIw/xqHk7POpDgRAhdJj59q5QYipWt0BFSMhUVd3kjITc2cCpPVnv4VrAWV2gnDUSWK9tO/UQSR4VZigV+E8PFH5IiCYZ5EJ3OTIYYwKkszRDiRl5Bx8AjS8CbsRYBr8whrJ9lTjYHtDO9dxk/T1Xev99qkxx6XXqPUnw/3T/t99DedZEwclET76220cH+hK5eThetw7ycog5jZvIArPIVg4acn0JuirN+IXIjm8RmTnf9fIuciYTTZl2VKqQSxIpwQvXXs3Exvk2Tns+IEix/KKq7PUoSygzWd6jo4Qqk+2DjcW/YKShlRbKmzp2Aty6/ioqcFJZCu3MdiQKEkyqAxFA/0bt/v9AXqvva9w1ba7jiWzMiizY2Qvu3DkmYj0bOsd9XU3oUSIHo5SlqST+ZEpzXKOMYvPobLOkq3V8bbJwVuOMVrsHH37BcSmUBx+yuhqZHMiD22jXc/Anf0rALyiMTOIcj5BhkmISoT8WAYvXrUUIXFyiFV7HBYuZVUZkdF1NC6kagICMjU5cMYeY5xFB/gVH7cfE5pDZzpgmVx4FUHJ+NCDeO/C08cUID1OdxzYhrDdWPdLhq1YiKTTsoBrRQ8AvFLNyxlTOqwykRpusCvA2wHIOsnGrRGSqNsmF0zA/5avW4wuGRsogLt9ZLI2uXhrcpMLpREolPbVDV+VjrOTLkMxAG9fE5FMOFvyaOJOyKAZdq0FTwzrr8DUrp7Dlro/CvWrHDF0SMBTeOiTEjK0LVsHlNtFrikYO7kEVc1t1s7cY1L1Edfl5yep+hbj3HQDDRggsL/STOjoe3w0seVX8CZBKlApSEOBY8noKHVjHWVHBj8/75ud/Xe7XlRZOs/Qv0vNN/FtZvqz1b8OsIiCNIktcq/Q6gYhsXyRdRyFGJKaVjVfGQYzwh8iNfNkkgK5ph3dPtX7BJUV39M9/jbKuqzlO99qRAX9iU0=",
            Base64.NO_WRAP);

    public static final byte[] aes256_gcm_key = Base64.decode("+4CU3S7ds9gAS7eRNAI8or5N6bZoqeRgir3yEw6L7Lg=",
            Base64.NO_WRAP);
    public static final byte[] aes256_gcm_nonce = Base64.decode("SRoU4TtZHPLznalr",
            Base64.NO_WRAP);
    public static final byte[] aes256_gcm_encrypted_data = Base64.decode("s+LtklAfiw+hkJ0PyUXWHw7VBsGI1PDN2Md5gFk0QNaiA1ouoQuU3kEBEzbXGDUGK0/WE8hkXCO3OwOKAndxWe1ZWw7czcivtoAZQmey/epTq7O5K7NVYWmZ+Yso7pATQ+x2V+3BDPPpXWFkq5reeV+38/Pn0wwwvJwqXYs3Vbr5oCin9rCI45wTo23b/L8XRjXiRBC5JyzOwKrlB9axTMt/q/9Nlkr8K3HEv5Nk6ZYFUyHAjIRUyrBVAeQsWguP6pAay4NIM2KebQVChtAS6uLC5XGpwNVMSHpkgNLtkKwHHlqEuEFZAlA+NDPs1gTXOYXxHbEUKuCjzhUSIKEZA3rDd+aQsgI3Ap046ryLVJp2QB7u88G+P5Owqaehx8meCm1ANzLRlSSTklKswQIRcKYJd2egtr9io6MNb3+q+uHu2DRdc6iMdxRB1/FUM+OteF3t1BiugF0TtaRSjZD1Ezsn9ZmTVoRiWsfu2aTpo11Cr2oK6qfppyO9XCAGWIkWBphd6Tl+dTQQSL5gC9jIc7qohdTcpm6I9XwHLoU0JD6vhMs5WoZZ15xO6KQzgc/WkUkmpvpDQdrk8MVkZH5m0m9/YSWBfvqeMjyTGrMzCs5oHWiPJepREbHxfxLQW/zAiBrSzjW/XSsuJ+IRA7J+L+12tVMq68JEwKKgVUA0yuehrssszHuV83XtaeEzOpYt7pCtLeKDJUDAH+ihQEldcxdTuz82sR8womLzhIgY8z+vUgBoBeQz5LWMo9jTac6ccuHJyj6wfmOMF+ptZwfCgT0JmnKN/imSZz0w9b+wxxnBv8Aq67zm4A9OVDwrAC8YuNiZ4n7HBJYxTRj9wm1biTTAekrGNEcUyHHjCW5W6zqU3HlUg4nj+MvpPBwELLrsKGm8UuR+3qGvSHRmhxaXT9A6UPU4Ocv5Ytbax/bpfqSsFkkczuBvDbDGf4iFnFjF5JKmr1EEP6dD8seat6bxLYI6siBYVPK7Ik75FEixKSgvxkrkFj5to64ZrAndtmphUmcW8hZybiTqxrz+rRRFnDCHMvNpu4oE2Nc2Z3n8/uzzsisTHTAyYfHMelXOuWA//HP7mrxyTMSgp+J4mLrl5ri3Bidw/Pw7d9ngPRo9reVBNCS7NwG3vbOLqKfEyIOVqv/mkSFq8xp0eRLvnA4uV2TZOBTJ435q+AssSgGm1ZIRPTh2DBbQOang5fSzpQ0vJFPaPlsbmJ5W00aV6JNQsQdJb6/4dabN9aMHxbxCQNM3UhQY2gcnUI2BBfpvQXG1NHM030XqIqug+chncnzlZpGkarBhlTovFa47YDZsSTPBsEfS6/6gNWXDVnznFhF8fkQ+tRhwU8kSKzw15QbkQmrCMiGYvMMIx8oM/WLl4rM=",
            Base64.NO_WRAP);
    public static final byte[] aes256_gcm_auth_data = Base64.decode("nYxnNFRnl8WBubHQ1PBbJ/4FOb0BZV0tGooUic34BCKHU9dycr9t7RnUemq9YoHqlZHUvMG+IiMF/faJxfqkwRMxz/v0IhVGm4H2G0BBXYHMNxYeXAJYpnZCubisYn1uOfQ+SF4f9SKsdCoH3vo1aa61mZDLRMTz2VL4EZ/xER0=",
            Base64.NO_WRAP);
    public static final byte[] aes256_gcm_auth_out = Base64.decode("s+LtklAfiw+hkJ0PyUXWHw7VBsGI1PDN2Md5gFk0QNaiA1ouoQuU3kEBEzbXGDUGK0/WE8hkXCO3OwOKAndxWe1ZWw7czcivtoAZQmey/epTq7O5K7NVYWmZ+Yso7pATQ+x2V+3BDPPpXWFkq5reeV+38/Pn0wwwvJwqXYs3Vbr5oCin9rCI45wTo23b/L8XRjXiRBC5JyzOwKrlB9axTMt/q/9Nlkr8K3HEv5Nk6ZYFUyHAjIRUyrBVAeQsWguP6pAay4NIM2KebQVChtAS6uLC5XGpwNVMSHpkgNLtkKwHHlqEuEFZAlA+NDPs1gTXOYXxHbEUKuCjzhUSIKEZA3rDd+aQsgI3Ap046ryLVJp2QB7u88G+P5Owqaehx8meCm1ANzLRlSSTklKswQIRcKYJd2egtr9io6MNb3+q+uHu2DRdc6iMdxRB1/FUM+OteF3t1BiugF0TtaRSjZD1Ezsn9ZmTVoRiWsfu2aTpo11Cr2oK6qfppyO9XCAGWIkWBphd6Tl+dTQQSL5gC9jIc7qohdTcpm6I9XwHLoU0JD6vhMs5WoZZ15xO6KQzgc/WkUkmpvpDQdrk8MVkZH5m0m9/YSWBfvqeMjyTGrMzCs5oHWiPJepREbHxfxLQW/zAiBrSzjW/XSsuJ+IRA7J+L+12tVMq68JEwKKgVUA0yuehrssszHuV83XtaeEzOpYt7pCtLeKDJUDAH+ihQEldcxdTuz82sR8womLzhIgY8z+vUgBoBeQz5LWMo9jTac6ccuHJyj6wfmOMF+ptZwfCgT0JmnKN/imSZz0w9b+wxxnBv8Aq67zm4A9OVDwrAC8YuNiZ4n7HBJYxTRj9wm1biTTAekrGNEcUyHHjCW5W6zqU3HlUg4nj+MvpPBwELLrsKGm8UuR+3qGvSHRmhxaXT9A6UPU4Ocv5Ytbax/bpfqSsFkkczuBvDbDGf4iFnFjF5JKmr1EEP6dD8seat6bxLYI6siBYVPK7Ik75FEixKSgvxkrkFj5to64ZrAndtmphUmcW8hZybiTqxrz+rRRFnDCHMvNpu4oE2Nc2Z3n8/uzzsisTHTAyYfHMelXOuWA//HP7mrxyTMSgp+J4mLrl5ri3Bidw/Pw7d9ngPRo9reVBNCS7NwG3vbOLqKfEyIOVqv/mkSFq8xp0eRLvnA4uV2TZOBTJ435q+AssSgGm1ZIRPTh2DBbQOang5fSzpQ0vJFPaPlsbmJ5W00aV6JNQsQdJb6/4dabN9aMHxbxCQNM3UhQY2gcnUI2BBfpvQXG1NHM030XqIqug+chncnzlZpGkarBhlTovFa47YDZsSTPBsEfS6/6gNWXDVnznFhF8fkQ+tRhwU8kSKzw15QbkQg==",
            Base64.NO_WRAP);
    public static final byte[] aes256_gcm_auth_tag = Base64.decode("ZeJtcVEH8xR9DGxecK/RHQ==",
            Base64.NO_WRAP);

    public static final byte[] sha224_hash = Base64.decode("FkwKT7zIFzDpO+YCq/XzYDG7GgIoPON95mlwYQ==",
            Base64.NO_WRAP);
    public static final byte[] sha256_hash = Base64.decode("ZagJz3SkarIx8ZwKfUSycc8qzChJk1Ehblx3tJpLdKA=",
            Base64.NO_WRAP);
    public static final byte[] sha384_hash = Base64.decode("x2wOiOkl3R9M4rCTSzI8B3Fu+r5tCDCfIXeioHj8gXohihi9+s4LOR89cPcNfAeU",
            Base64.NO_WRAP);
    public static final byte[] sha512_hash = Base64.decode("dwQYglm3VdtcqhlYW/szvTdYwu1KbdHqllyL7G20u8aZeVNtHWmfp1Vd+AcKVymfIFFLQRrG7lSHF3HfePQDLg==",
            Base64.NO_WRAP);

}
