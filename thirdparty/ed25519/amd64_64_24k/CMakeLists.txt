# Just define ed25519 implementation source files

file(GLOB src_c "*.c")
file(GLOB src_s "*.s")
set(src_ed25519_impl "${src_c}" "${src_s}" CACHE INTERNAL "")
