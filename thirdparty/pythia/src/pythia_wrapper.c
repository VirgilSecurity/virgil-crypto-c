/**
 * Copyright (C) 2015-2018 Virgil Security Inc.

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "pythia_c.h"
#include "pythia_buf_exports.h"
#include "pythia_conf.h"
#include "pythia_init.h"
#include "pythia_init_c.h"
#include "pythia_wrapper.h"

#include <relic/relic_bn.h>

int pythia_w_blind(const pythia_buf_t *password, pythia_buf_t *blinded_password, pythia_buf_t *blinding_secret) {
    pythia_err_init();

    g1_t blinded_ep; g1_null(blinded_ep);
    bn_t rInv_bn; bn_null(rInv_bn);

    TRY {
        g1_new(blinded_ep);
        bn_new(rInv_bn);

        pythia_blind(password->p, password->len, blinded_ep, rInv_bn);

        g1_write_buf(blinded_password, blinded_ep);
        bn_write_buf(blinding_secret, rInv_bn);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        bn_free(rInv_bn);
        g1_free(blinded_ep);
    }

    return 0;
}

int pythia_w_deblind(const pythia_buf_t *transformed_password, const pythia_buf_t *blinding_secret,
                     pythia_buf_t *deblinded_password) {
    pythia_err_init();

    gt_t a_gt; gt_null(a_gt);
    gt_t y_gt; gt_null(y_gt);
    bn_t rInv_bn; bn_null(rInv_bn);

    TRY {
        gt_new(a_gt);
        gt_new(y_gt);
        gt_read_buf(y_gt, transformed_password);

        bn_new(rInv_bn);
        bn_read_buf(rInv_bn, blinding_secret);

        pythia_deblind(y_gt, rInv_bn, a_gt);

        gt_write_buf(deblinded_password, a_gt);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        bn_free(rInv_bn);
        gt_free(y_gt);
        gt_free(a_gt);
    }

    return 0;
}

int pythia_w_compute_transformation_key_pair(const pythia_buf_t *transformation_key_id,
                                             const pythia_buf_t *pythia_secret,
                                             const pythia_buf_t *pythia_scope_secret,
                                             pythia_buf_t *transformation_private_key,
                                             pythia_buf_t *transformation_public_key) {
    pythia_err_init();

    bn_t kw; bn_null(kw);
    g1_t pi_p; g1_null(pi_p);

    TRY {
        bn_new(kw);
        g1_new(pi_p);

        pythia_compute_kw(transformation_key_id->p, transformation_key_id->len, pythia_secret->p, pythia_secret->len,
                          pythia_scope_secret->p, pythia_scope_secret->len, kw, pi_p);

        bn_write_buf(transformation_private_key, kw);
        g1_write_buf(transformation_public_key, pi_p);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        bn_free(kw);
        g1_free(pi_p);
    }

    return 0;
}

int pythia_w_transform(const pythia_buf_t *blinded_password, const pythia_buf_t *tweak,
                       const pythia_buf_t *transformation_private_key, pythia_buf_t *transformed_password,
                       pythia_buf_t *transformed_tweak) {
    pythia_err_init();

    gt_t y_gt; gt_null(y_gt);
    bn_t kw_bn; bn_null(kw_bn);
    g2_t tTilde_g2; g2_null(tTilde_g2);
    g1_t x_ep; g1_null(x_ep);

    TRY {
        gt_new(y_gt);
        bn_new(kw_bn);
        g2_new(tTilde_g2);
        g1_new(x_ep);

        g1_read_buf(x_ep, blinded_password);
        bn_read_buf(kw_bn, transformation_private_key);

        pythia_eval(x_ep, tweak->p, tweak->len, kw_bn, y_gt, tTilde_g2);

        gt_write_buf(transformed_password, y_gt);
        g2_write_buf(transformed_tweak, tTilde_g2);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        g1_free(x_ep);
        g2_free(tTilde_g2);
        bn_free(kw_bn);
        gt_free(y_gt);
    }

    return 0;
}

int pythia_w_prove(const pythia_buf_t *transformed_password, const pythia_buf_t *blinded_password,
                   const pythia_buf_t *transformed_tweak, const pythia_buf_t *transformation_private_key,
                   const pythia_buf_t *transformation_public_key,
                   pythia_buf_t *proof_value_c, pythia_buf_t *proof_value_u) {
    pythia_err_init();

    g1_t pi_p; g1_null(pi_p);
    bn_t c_bn; bn_null(c_bn);
    bn_t u_bn; bn_null(u_bn);
    g1_t x_g1; g1_null(x_g1);
    g2_t tTilde_g2; g2_null(tTilde_g2);
    bn_t kw_bn; bn_null(kw_bn);
    gt_t y_gt; gt_null(y_gt);

    TRY {
        g1_new(x_g1);
        g1_read_buf(x_g1, blinded_password);

        g2_new(tTilde_g2);
        g2_read_buf(tTilde_g2, transformed_tweak);

        bn_new(kw_bn);
        bn_read_buf(kw_bn, transformation_private_key);

        g1_new(pi_p);
        g1_read_buf(pi_p, transformation_public_key);

        gt_new(y_gt);
        gt_read_buf(y_gt, transformed_password);

        bn_new(c_bn);
        bn_new(u_bn);
        pythia_prove(y_gt, x_g1, tTilde_g2, kw_bn, pi_p, c_bn, u_bn);

        bn_write_buf(proof_value_c, c_bn);
        bn_write_buf(proof_value_u, u_bn);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        g1_free(pi_p);
        gt_free(y_gt);
        bn_free(kw_bn);
        g2_free(tTilde_g2);
        g1_free(x_g1);
        bn_free(u_bn);
        bn_free(c_bn);
    }

    return 0;
}

int pythia_w_verify(const pythia_buf_t *transformed_password, const pythia_buf_t *blinded_password,
                    const pythia_buf_t *tweak, const pythia_buf_t *transformation_public_key,
                    const pythia_buf_t *proof_value_c, const pythia_buf_t *proof_value_u, int *verified) {
    pythia_err_init();

    g1_t x_g1; g1_null(x_g1);
    gt_t y_gt; gt_null(y_gt);
    g1_t p_g1; g1_null(p_g1);
    bn_t c_bn; bn_null(c_bn);
    bn_t u_bn; bn_null(u_bn);

    TRY {
        g1_new(x_g1);
        g1_read_buf(x_g1, blinded_password);

        gt_new(y_gt);
        gt_read_buf(y_gt, transformed_password);

        g1_new(p_g1);
        g1_read_buf(p_g1, transformation_public_key);

        bn_new(c_bn);
        bn_read_buf(c_bn, proof_value_c);

        bn_new(u_bn);
        bn_read_buf(u_bn, proof_value_u);

        pythia_verify(y_gt, x_g1, tweak->p, tweak->len, p_g1, c_bn, u_bn, verified);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        gt_free(y_gt);
        g1_free(x_g1);
        bn_free(u_bn);
        bn_free(c_bn);
        g1_free(p_g1);
    }

    return 0;
}

int pythia_w_get_password_update_token(const pythia_buf_t *previous_transformation_private_key,
                                       const pythia_buf_t *new_transformation_private_key,
                                       pythia_buf_t *password_update_token) {
    pythia_err_init();

    bn_t delta_bn; bn_null(delta_bn);
    bn_t kw0; bn_null(kw0);
    bn_t kw1; bn_null(kw1);

    TRY {
        bn_new(kw0);
        bn_read_buf(kw0, previous_transformation_private_key);

        bn_new(kw1);
        bn_read_buf(kw1, new_transformation_private_key);

        bn_new(delta_bn);
        get_delta(kw0, kw1, delta_bn);

        bn_write_buf(password_update_token, delta_bn);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        bn_free(delta_bn);
        bn_free(kw0);
        bn_free(kw1);
    }

    return 0;
}

int pythia_w_update_deblinded_with_token(const pythia_buf_t *deblinded_password,
                                         const pythia_buf_t *password_update_token,
                                         pythia_buf_t *updated_deblinded_password) {
    pythia_err_init();

    gt_t r_gt; gt_null(r_gt);
    gt_t z_gt; gt_null(z_gt);
    bn_t delta_bn; bn_null(delta_bn);

    TRY {
        gt_new(r_gt);
        gt_new(z_gt);
        gt_read_buf(z_gt, deblinded_password);

        bn_new(delta_bn);
        bn_read_buf(delta_bn, password_update_token);

        pythia_update_with_delta(z_gt, delta_bn, r_gt);

        gt_write_buf(updated_deblinded_password, r_gt);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        bn_free(delta_bn);
        gt_free(z_gt);
        gt_free(r_gt);
    }

    return 0;
}
