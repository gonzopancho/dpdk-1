cmake_minimum_required(VERSION 2.8.4)
project(routemario)

add_definitions(-g -Wall -Wconversion -Woverflow)
add_definitions(-O1)
add_definitions(-msse4.2)
#add_definitions(-march=corei7)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

# DPDK
set(dpdk_DIR /home/tkk/dev/dpdk)
set(RTE_SDK ${dpdk_DIR})
set(RTE_TARGET x86_64-native-linuxapp-gcc)
add_definitions(-DUSE_DPDK)
add_definitions(-isystem ${RTE_SDK}/${RTE_TARGET}/include -include rte_config.h)
link_directories(${LINK_DIRECTORIES} ${RTE_SDK}/${RTE_TARGET}/lib)
set(RTE_LIBRARIES ${RTE_LIBRARIES} rte_eal ethdev rte_mbuf rte_kvargs rte_malloc rte_mempool rte_ring)
set(RTE_LIBRARIES ${RTE_LIBRARIES} rte_pmd_ixgbe rte_pmd_ring)
set(RTE_LIBRARIES ${RTE_LIBRARIES} rte_hash) 

# LIST OF RTE_LIB
#ethdev rte_acl rte_cfgfile rte_cmdline rte_distributor rte_eal rte_hash rte_ip_frag rte_jobstats rte_kni rte_kvargs rte_lpm rte_malloc rte_mbuf rte_mempool rte_meter rte_pipeline rte_pmd_af_packet rte_pmd_bond rte_pmd_e1000 rte_pmd_enic rte_pmd_fm10k rte_pmd_i40e rte_pmd_ixgbe rte_pmd_null rte_pmd_ring rte_port rte_power rte_reorder rte_ring rte_sched rte_table rte_timer)

# LIBRARY
set(LIBRARIES -Wl,--whole-archive ${LIBRARIES} ${RTE_LIBRARIES} pthread rt dl m -Wl,--no-whole-archive)

set(routemario_SRC main.c)
set(fdb_SRC fdb.c)
set(test_fdb_SRC test_fdb.c)
set(arp_SRC arp.c)
#set(test_arp_SRC test_arp.c)
set(ipv4_SRC ipv4.c)

add_library(fdb ${fdb_SRC})
add_library(arp ${arp_SRC})
add_library(ipv4  ${ipv4_SRC})
set(RM_LIBRARIES fdb arp ipv4)
set(LIBRARIES -Wl,--whole-archive ${LIBRARIES} ${RM_LIBRARIES} ${RTE_LIBRARIES} pthread rt dl m -Wl,--no-whole-archive)
add_executable(test_fdb ${test_fdb_SRC})
target_link_libraries(test_fdb ${LIBRARIES} fdb)
#add_executable(test_arp ${test_arp_SRC})
#target_link_libraries(test_arp ${LIBRARIES} arp)
add_executable(routemario ${routemario_SRC})
target_link_libraries(routemario ${RM_LIBRARIES} ${LIBRARIES})
