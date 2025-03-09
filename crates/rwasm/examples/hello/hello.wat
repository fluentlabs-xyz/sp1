(module
      (func $main
        i32.const 4
        call $fib
        drop
        )
     (func $fib  (param $n i32) (result i32)
    local.get $n
    i32.const 2
    i32.lt_s
    if
      i32.const 1
      return
    end
    local.get $n
    i32.const 2
    i32.sub
    call $fib
    local.get $n
    i32.const 1
    i32.sub
    call $fib
    i32.add
    return
  )
      (export "main" (func $main)))