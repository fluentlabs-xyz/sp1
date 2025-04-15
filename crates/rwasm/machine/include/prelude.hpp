#pragma once

#include "rwasm-machine-sys-cbindgen.hpp"

#ifndef __CUDACC__
#define __SP1_HOSTDEV__
#define __SP1_INLINE__ inline
#include <array>

namespace rwasm_machine_sys {
template <class T, std::size_t N>
using array_t = std::array<T, N>;
}  // namespace rwasm_machine_sys
#else
#define __SP1_HOSTDEV__ __host__ __device__
#define __SP1_INLINE__
#include <cuda/std/array>

namespace rwasm_machine_sys {
template <class T, std::size_t N>
using array_t = cuda::std::array<T, N>;
}  // namespace rwasm_machine_sys
#endif
