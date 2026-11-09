set(eapp_bin hsm-eapp)
set(eapp_src
  start.S
  hsm_eapp.c
  key_store.c
  crypto_aes.c
  crypto_sha256.c
  crypto_prng.c
)

set(host_bin test_pkcs11_hsm)
set(host_src
  hsm_host.cpp
)

set(package_name "hsm.ke")
set(package_script "./test_pkcs11_hsm hsm-eapp eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup rv32")
else()
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup")
endif()

# Enclave Application
add_executable(${eapp_bin} ${eapp_src})
target_include_directories(${eapp_bin} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${eapp_bin} ${KEYSTONE_LIB_EAPP} "-nostdlib" "-static" "-T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")

# Host / PKCS#11 Test Application
add_executable(${host_bin} ${host_src})
target_include_directories(${host_bin} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} -lpthread)

# Add Eyrie runtime for HSM
set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  "v1.0.0"
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# Add makeself package target
add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)
add_dependencies(examples ${eapp_bin}-package)
